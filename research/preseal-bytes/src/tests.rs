use crate::bytes::*;

const FIXTURE: &[u8] = include_bytes!("../fixtures/synthetic-job.bin");
const EXPECTED: [&str; 5] = [
    "13a534beffaaf23a1e45fb827722bc80ae2a5ffa92f51ea06fb69cd100f97b93aa03e7babf148193d441387f222bf07b484d3f5e9f7915fc92720f07168a3481",
    "c5ca0a735050b3ab7bbee54f9478f7a4b61ecbc27fd3959e0aa581cfda5e3e7e528e88e676493af332017a58f13bd31549b13e9bd865ee52a7aef874fd1802d0",
    "a83e0199f5f5f608b39df27e548a7d59ce58ed3e535610de766e1114856ae4c63f6c4afe420497a2905a0ca034865317355eb2590079b3a7d38e555445bafa50",
    "2a48d4e806c04a79619c48a20d619a006e4ee83306a2e0d8f810201e60ae5a2ddcd78f56eb3027a3e66f8af7812d1ed2a16e5c2aed7d19db20ac7cae07f4f5d8",
    "6fb3398e1bec6af2f1fe96311b9338ab8cd99596dceae277549b44e17acf19e0c0b7e8fa7b4a0bceb190aaf330a1c0935e834e89ffd86283a53338ea42f10ca1",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Independent test walk records mutation offsets, not production parsing authority.
fn locations() -> Vec<(usize, usize)> {
    let mut offset = 8;
    let mut fields = Vec::new();
    while offset < FIXTURE.len() {
        let length = u32::from_be_bytes(FIXTURE[offset..offset + 4].try_into().unwrap()) as usize;
        fields.push((offset, length));
        offset += 4 + length;
    }
    assert_eq!(offset, 927);
    assert_eq!(fields.len(), 25);
    fields
}

fn length_at(fields: &[(usize, usize)], index: usize, length: u32) -> Vec<u8> {
    let mut bytes = FIXTURE.to_vec();
    let offset = fields[index].0;
    bytes[offset..offset + 4].copy_from_slice(&length.to_be_bytes());
    bytes
}

#[test]
#[ignore = "finite external resource admission required"]
fn bounded_job_controls() {
    assert_eq!(
        std::env::var("KOVA_PRESEAL_BYTES_ADMISSION").as_deref(),
        Ok("v75-native-1")
    );
    let original = parse(FIXTURE).unwrap();
    assert_eq!(original.records().len(), 2);
    assert!(original.as_bytes().as_ptr() == FIXTURE.as_ptr());
    assert_eq!(hex(&original.job_id()), EXPECTED[0]);
    for i in 0..2 {
        let ids = original.record_ids(i).unwrap();
        assert_eq!(hex(&ids.effect), EXPECTED[1 + 2 * i]);
        assert_eq!(hex(&ids.authorization), EXPECTED[2 + 2 * i]);
    }
    assert!(original.record_ids(2).is_none());
    assert!(original.record_ids(usize::MAX).is_none());
    let encoded = encode(original.context(), original.records()).unwrap();
    assert_eq!(encoded.as_bytes(), FIXTURE);
    assert_eq!(encoded.requested_capacity(), 927);
    assert!(encoded.observed_capacity() >= encoded.requested_capacity());
    let restored = parse(encoded.as_bytes()).unwrap();
    assert_eq!(restored.job_id(), original.job_id());
    assert_eq!(restored.context().height, 42);
    assert_eq!(restored.context().timestamp, 1700000000);
    assert_eq!(restored.context().epoch, 7);
    assert_eq!(restored.context().treasury_policy, b"treasury:synthetic:v1");
    assert_eq!(restored.records()[0].recovery, b"");
    assert_eq!(
        restored.records()[1].recovery,
        b"encrypted:public-recovery:beta"
    );

    let fields = locations();
    let mut mutated_frames = 0;
    for i in (1..=13).chain([15, 16, 17, 18, 20, 21, 22, 23, 24]) {
        let mut bytes = FIXTURE.to_vec();
        let (offset, length) = fields[i];
        bytes[offset + 3 + length] ^= if i == 15 { 3 } else { 1 };
        let changed = parse(&bytes).unwrap();
        assert_ne!(changed.job_id(), original.job_id());
        mutated_frames += 1;
    }
    assert_eq!(mutated_frames, 22);
    let mut changed_records = original.records().to_vec();
    changed_records[0].authorization = b"canonical-outer-but-not-a-valid-proof";
    let changed = encode(original.context(), &changed_records).unwrap();
    let changed = parse(changed.as_bytes()).unwrap();
    let before = original.record_ids(0).unwrap();
    let after = changed.record_ids(0).unwrap();
    assert_eq!(before.effect, after.effect);
    assert_ne!(before.authorization, after.authorization);
    assert_ne!(original.job_id(), changed.job_id());
    // No cryptographic validity result exists in the byte API.
    assert_eq!(
        changed.records()[0].authorization,
        b"canonical-outer-but-not-a-valid-proof"
    );

    let records = original.records();
    let reversed = [records[1], records[0]];
    let swapped_auth = [
        PublicRecord {
            authorization: records[1].authorization,
            ..records[0]
        },
        PublicRecord {
            authorization: records[0].authorization,
            ..records[1]
        },
    ];
    let swapped_effect = [
        PublicRecord {
            effect: records[1].effect,
            ..records[0]
        },
        PublicRecord {
            effect: records[0].effect,
            ..records[1]
        },
    ];
    let swapped_recovery = [
        PublicRecord {
            recovery: records[1].recovery,
            ..records[0]
        },
        PublicRecord {
            recovery: records[0].recovery,
            ..records[1]
        },
    ];
    for alternative in [reversed, swapped_auth, swapped_effect, swapped_recovery] {
        let encoded = encode(original.context(), &alternative).unwrap();
        assert_ne!(
            parse(encoded.as_bytes()).unwrap().job_id(),
            original.job_id()
        );
    }

    let empty = encode(original.context(), &[]).unwrap();
    assert_eq!(empty.as_bytes().len(), 631);
    assert!(parse(empty.as_bytes()).unwrap().records().is_empty());
    let policy = [b'p'; MAX_POLICY];
    let payload = [b'x'; MAX_PAYLOAD];
    let maximum = [PublicRecord {
        kind: 4,
        class: records[0].class,
        effect: &payload,
        authorization: &payload,
        recovery: &payload,
    }; MAX_RECORDS];
    let maximum_context = PublicContext {
        treasury_policy: &policy,
        ..original.context()
    };
    let max_encoded = encode(maximum_context, &maximum).unwrap();
    assert_eq!(max_encoded.as_bytes().len(), 51130);
    assert_eq!(max_encoded.requested_capacity(), 51130);
    assert_eq!(parse(max_encoded.as_bytes()).unwrap().records().len(), 4);
    assert!(matches!(
        encode(original.context(), &[records[0]; 5]),
        Err(Error::Count)
    ));
    let too_large = [0; MAX_PAYLOAD + 1];
    for field in 0..3 {
        let mut r = records[0];
        match field {
            0 => r.effect = &too_large,
            1 => r.authorization = &too_large,
            _ => r.recovery = &too_large,
        }
        assert!(matches!(
            encode(original.context(), &[r]),
            Err(Error::FieldLimit)
        ));
    }
    let policy_large = [0; MAX_POLICY + 1];
    assert!(matches!(
        encode(
            PublicContext {
                treasury_policy: &policy_large,
                ..original.context()
            },
            records
        ),
        Err(Error::FieldLimit)
    ));
    assert!(matches!(
        encode(
            PublicContext {
                target_le: &[0; 32],
                ..original.context()
            },
            records
        ),
        Err(Error::ZeroTarget)
    ));
    assert!(matches!(
        encode(
            original.context(),
            &[PublicRecord {
                kind: 5,
                ..records[0]
            }]
        ),
        Err(Error::Kind)
    ));

    let fixed_indices: Vec<_> = (0..=12).chain([14, 15, 16, 20, 21]).collect();
    for &i in &fixed_indices {
        assert!(matches!(
            parse(&length_at(&fields, i, 0)),
            Err(Error::Width)
        ));
    }
    assert_eq!(fixed_indices.len(), 18);
    for i in [13, 17, 18, 19, 22, 23, 24] {
        let cap = if i == 13 { MAX_POLICY } else { MAX_PAYLOAD };
        assert!(matches!(
            parse(&length_at(&fields, i, (cap + 1) as u32)),
            Err(Error::FieldLimit)
        ));
        assert!(matches!(
            parse(&length_at(&fields, i, u32::MAX)),
            Err(Error::FieldLimit)
        ));
    }
    for count in [5_u32, u32::MAX] {
        let mut bytes = FIXTURE.to_vec();
        let offset = fields[14].0 + 4;
        bytes[offset..offset + 4].copy_from_slice(&count.to_be_bytes());
        assert!(matches!(parse(&bytes), Err(Error::Count)));
    }
    for kind in [0_u16, 5] {
        let mut bytes = FIXTURE.to_vec();
        let offset = fields[15].0 + 4;
        bytes[offset..offset + 2].copy_from_slice(&kind.to_be_bytes());
        assert!(matches!(parse(&bytes), Err(Error::Kind)));
    }
    let mut bytes = FIXTURE.to_vec();
    bytes[0] ^= 1;
    assert!(matches!(parse(&bytes), Err(Error::Magic)));
    let mut bytes = FIXTURE.to_vec();
    bytes[13] = 2;
    assert!(matches!(parse(&bytes), Err(Error::Version)));
    let mut bytes = FIXTURE.to_vec();
    bytes[fields[11].0 + 4..fields[11].0 + 36].fill(0);
    assert!(matches!(parse(&bytes), Err(Error::ZeroTarget)));
    let mut bytes = FIXTURE.to_vec();
    bytes.extend_from_slice(&[0]);
    assert!(matches!(parse(&bytes), Err(Error::Trailing)));
    assert!(matches!(parse(&[0; MAX_TOTAL + 1]), Err(Error::Total)));
    let mut bytes = FIXTURE.to_vec();
    bytes[8..12].reverse();
    assert!(matches!(parse(&bytes), Err(Error::Width)));
    for end in 0..FIXTURE.len() {
        assert!(parse(&FIXTURE[..end]).is_err());
    }
    assert!(matches!(
        parse(&FIXTURE[..FIXTURE.len() - 1]),
        Err(Error::Truncated)
    ));
    internal_controls();
    println!(
        "{{\"independent_ids\":5,\"fixture_bytes\":927,\"maximum_bytes\":51130,\"mutated_frames\":22,\"association_controls\":4,\"fixed_width_refusals\":18,\"variable_length_refusals\":14,\"truncated_prefixes\":927,\"requested_capacity\":{},\"observed_capacity\":{}}}",
        encoded.requested_capacity(),
        encoded.observed_capacity()
    );
}
