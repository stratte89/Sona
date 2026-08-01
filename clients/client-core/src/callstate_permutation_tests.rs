use super::*;

fn id(byte: u8) -> String {
    format!("{byte:02x}").repeat(16)
}

fn permutations<T: Copy>(items: &[T]) -> Vec<Vec<T>> {
    fn visit<T: Copy>(items: &mut [T], index: usize, out: &mut Vec<Vec<T>>) {
        if index == items.len() {
            out.push(items.to_vec());
            return;
        }
        for candidate in index..items.len() {
            items.swap(index, candidate);
            visit(items, index + 1, out);
            items.swap(index, candidate);
        }
    }

    let mut items = items.to_vec();
    let mut out = Vec::new();
    visit(&mut items, 0, &mut out);
    out
}

#[derive(Clone, Copy)]
enum RingEvent {
    Offer,
    Terminal,
}

#[test]
fn every_offer_terminal_duplicate_order_converges_without_a_late_ring() {
    let call = id(1);
    let ring = id(2);
    for sequence in permutations(&[
        RingEvent::Offer,
        RingEvent::Offer,
        RingEvent::Terminal,
        RingEvent::Terminal,
    ]) {
        let mut registry = CallRegistry::default();
        let mut terminal_seen = false;
        let mut rings = 0;
        for (offset, event) in sequence.into_iter().enumerate() {
            let now = 101 + offset as u64;
            match event {
                RingEvent::Offer => {
                    let decision = registry.receive_offer(&call, &ring, 100, 145, now, 0);
                    if decision == OfferDecision::Ring {
                        assert!(!terminal_seen, "an offer rang after its terminal");
                        rings += 1;
                    }
                }
                RingEvent::Terminal => {
                    let decision = registry.record_terminal(
                        &call,
                        &ring,
                        CallTerminalReason::AnsweredElsewhere,
                        now,
                        0,
                    );
                    assert!(matches!(
                        decision,
                        TerminalDecision::Applied(CallTerminalReason::AnsweredElsewhere)
                            | TerminalDecision::Duplicate(CallTerminalReason::AnsweredElsewhere)
                    ));
                    terminal_seen = true;
                }
            }
        }
        assert!(rings <= 1);
        assert_eq!(
            registry.terminal_reason(&call),
            Some(CallTerminalReason::AnsweredElsewhere)
        );
        assert_eq!(
            registry.receive_offer(&call, &ring, 100, 145, 110, 0),
            OfferDecision::Suppressed(CallTerminalReason::AnsweredElsewhere)
        );
    }
}

#[test]
fn every_competing_claim_order_has_exactly_one_stable_winner() {
    let call = id(1);
    let offer = id(2);
    let claims = [
        AnswerClaim {
            call_instance_id: call.clone(),
            offer_id: offer.clone(),
            claim_nonce: id(3),
            answering_device_id: id(4),
            reply_to_mailbox: "a".repeat(64),
        },
        AnswerClaim {
            call_instance_id: call.clone(),
            offer_id: offer.clone(),
            claim_nonce: id(5),
            answering_device_id: id(6),
            reply_to_mailbox: "b".repeat(64),
        },
    ];
    for sequence in permutations(&[0usize, 0, 1, 1]) {
        let expected = &claims[sequence[0]];
        let mut arbiter = AnswerArbiter::new(call.clone(), offer.clone());
        let mut winner_decisions = 0;
        for claim_index in sequence {
            let decision = arbiter.claim(&claims[claim_index]);
            let winner = match decision {
                ClaimDecision::Winner(winner) => {
                    winner_decisions += 1;
                    winner
                }
                ClaimDecision::Duplicate(winner) | ClaimDecision::Lost(winner) => winner,
                ClaimDecision::Invalid => panic!("all generated claims are valid"),
            };
            assert_eq!(winner.claim_nonce, expected.claim_nonce);
            assert_eq!(winner.answering_device_id, expected.answering_device_id);
            assert_eq!(winner.reply_to_mailbox, expected.reply_to_mailbox);
        }
        assert_eq!(winner_decisions, 1);
        assert_eq!(
            arbiter.winner().map(|winner| &winner.claim_nonce),
            Some(&expected.claim_nonce)
        );
    }
}

#[derive(Clone, Copy)]
enum ResumeEvent {
    First,
    Second,
    Terminal,
}

#[test]
fn resume_terminal_permutations_never_revive_a_logical_call() {
    let call = id(1);
    let initial = id(2);
    for sequence in permutations(&[
        ResumeEvent::First,
        ResumeEvent::Second,
        ResumeEvent::Terminal,
    ]) {
        let mut registry = CallRegistry::default();
        assert_eq!(
            registry.receive_offer(&call, &initial, 100, 145, 101, 0),
            OfferDecision::Ring
        );
        assert_eq!(
            registry.transition(&call, &initial, CallPhase::Winner, 102),
            TransitionDecision::Applied
        );
        assert_eq!(
            registry.transition(&call, &initial, CallPhase::Active, 103),
            TransitionDecision::Applied
        );
        let mut terminal_seen = false;
        for (offset, event) in sequence.into_iter().enumerate() {
            let now = 110 + offset as u64;
            match event {
                ResumeEvent::First | ResumeEvent::Second => {
                    let offer = match event {
                        ResumeEvent::First => id(3),
                        ResumeEvent::Second => id(4),
                        ResumeEvent::Terminal => unreachable!(),
                    };
                    let decision = registry.receive_resume(&call, &offer, now, now + 60, now);
                    if terminal_seen {
                        assert_eq!(
                            decision,
                            ResumeDecision::Suppressed(CallTerminalReason::CallerCancelled)
                        );
                    } else {
                        assert_eq!(decision, ResumeDecision::Accepted);
                    }
                }
                ResumeEvent::Terminal => {
                    assert_eq!(
                        registry.record_terminal(
                            &call,
                            &initial,
                            CallTerminalReason::CallerCancelled,
                            now,
                            0,
                        ),
                        TerminalDecision::Applied(CallTerminalReason::CallerCancelled)
                    );
                    terminal_seen = true;
                }
            }
        }
        assert_eq!(
            registry.terminal_reason(&call),
            Some(CallTerminalReason::CallerCancelled)
        );
        assert_eq!(
            registry.receive_resume(&call, &id(9), 120, 180, 120),
            ResumeDecision::Suppressed(CallTerminalReason::CallerCancelled)
        );
    }
}

#[test]
fn transition_table_is_monotonic_and_active_always_requires_winner() {
    let call = id(1);
    let offer = id(2);
    let phases = [
        CallPhase::Ringing,
        CallPhase::AnswerPendingUnlock,
        CallPhase::Claiming,
        CallPhase::Winner,
        CallPhase::Active,
    ];
    let targets = [
        CallPhase::Offered,
        CallPhase::Ringing,
        CallPhase::AnswerPendingUnlock,
        CallPhase::Claiming,
        CallPhase::Winner,
        CallPhase::Active,
    ];

    for current in phases {
        let mut base = CallRegistry::default();
        base.receive_offer(&call, &offer, 100, 145, 101, 0);
        if current == CallPhase::Active {
            base.transition(&call, &offer, CallPhase::Winner, 102);
            base.transition(&call, &offer, CallPhase::Active, 103);
        } else if current != CallPhase::Ringing {
            base.transition(&call, &offer, current, 102);
        }
        for target in targets {
            let expected = if target == current {
                TransitionDecision::Duplicate
            } else if target < current {
                TransitionDecision::Regressive
            } else if target == CallPhase::Active && current != CallPhase::Winner {
                TransitionDecision::Prerequisite
            } else {
                TransitionDecision::Applied
            };
            assert_eq!(
                base.clone().transition(&call, &offer, target, 104),
                expected,
                "{current:?} -> {target:?}"
            );
        }
    }
}

#[test]
fn expiry_and_clock_skew_boundaries_are_exact() {
    assert_eq!(
        CallRegistry::default().receive_offer(&id(1), &id(2), 100, 145, 144, 0),
        OfferDecision::Ring
    );
    assert_eq!(
        CallRegistry::default().receive_offer(&id(1), &id(2), 100, 145, 145, 0),
        OfferDecision::Expired
    );
    assert_eq!(
        CallRegistry::default().receive_offer(&id(1), &id(2), 105, 150, 100, 0),
        OfferDecision::Ring
    );
    assert_eq!(
        CallRegistry::default().receive_offer(&id(1), &id(2), 106, 151, 100, 0),
        OfferDecision::Invalid
    );
    assert!(!valid_control_expiry(95, 100));
    assert!(valid_control_expiry(96, 100));
    assert!(valid_control_expiry(165, 100));
    assert!(!valid_control_expiry(166, 100));
}
