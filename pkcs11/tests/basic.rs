#![cfg(feature = "pkcs11-full-tests")]

pub mod tools;

use pkcs11::{
    types::{CK_ATTRIBUTE, CK_OBJECT_HANDLE, CK_SESSION_HANDLE},
    Ctx,
};

use tools::constants::{RSA_MECHANISM, RSA_PRIVATE_KEY_ATTRIBUTES, RSA_PUBLIC_KEY_ATTRIBUTES};

#[test_log::test]
fn set_attribute_value() {
    tools::run_test(|ctx| {
        fn get_attributes(
            ctx: &Ctx,
            session: CK_SESSION_HANDLE,
            object: CK_OBJECT_HANDLE,
        ) -> (String, String) {
            let mut buffer1 = [0; 128];
            let mut buffer2 = [0; 128];
            let mut attributes = vec![
                CK_ATTRIBUTE {
                    attrType: pkcs11::types::CKA_ID,
                    pValue: buffer1.as_mut_ptr() as _,
                    ulValueLen: buffer1.len().try_into().unwrap(),
                },
                CK_ATTRIBUTE {
                    attrType: pkcs11::types::CKA_LABEL,
                    pValue: buffer2.as_mut_ptr() as _,
                    ulValueLen: buffer2.len().try_into().unwrap(),
                },
            ];
            ctx.get_attribute_value(session, object, &mut attributes)
                .unwrap();
            let id = String::from_utf8(attributes[0].get_bytes().unwrap()).unwrap();
            let label = String::from_utf8(attributes[1].get_bytes().unwrap()).unwrap();
            (id, label)
        }

        let slot = 0;
        let session = ctx.open_session(slot, 0x04, None, None).unwrap();
        let (public_key, private_key) = ctx
            .generate_key_pair(
                session,
                &RSA_MECHANISM,
                RSA_PUBLIC_KEY_ATTRIBUTES,
                RSA_PRIVATE_KEY_ATTRIBUTES,
            )
            .unwrap();

        let (public_id, public_label) = get_attributes(ctx, session, public_key);
        println!("public key: id = {public_id}, label = {public_label}");
        let (private_id, private_label) = get_attributes(ctx, session, private_key);
        println!("private key: id = {private_id}, label = {private_label}");

        let new_id = "mynewkeyid";
        ctx.set_attribute_value(
            session,
            private_key,
            &[CK_ATTRIBUTE::new(pkcs11::types::CKA_ID).with_bytes(new_id.as_bytes())],
        )
        .unwrap();

        let (public_id, public_label) = get_attributes(ctx, session, public_key);
        let (private_id, private_label) = get_attributes(ctx, session, private_key);
        assert_eq!(&public_id, new_id);
        assert_eq!(&public_label, "");
        assert_eq!(&private_id, new_id);
        assert_eq!(&private_label, "");

        ctx.destroy_object(session, private_key).unwrap();
    })
}

#[test_log::test]
fn delete() {
    tools::run_test(|ctx| {
        fn assert_objects(ctx: &Ctx, session: CK_SESSION_HANDLE, expected: &[CK_OBJECT_HANDLE]) {
            ctx.find_objects_init(session, &[]).unwrap();
            let mut objects = ctx.find_objects(session, 10).unwrap();
            ctx.find_objects_final(session).unwrap();

            let mut expected_objects = expected.to_vec();
            objects.sort();
            expected_objects.sort();
            assert_eq!(objects, expected_objects);
        }

        let slot = 0;
        let session = ctx.open_session(slot, 0x04, None, None).unwrap();
        let (public_key1, private_key1) = ctx
            .generate_key_pair(
                session,
                &RSA_MECHANISM,
                RSA_PUBLIC_KEY_ATTRIBUTES,
                RSA_PRIVATE_KEY_ATTRIBUTES,
            )
            .unwrap();
        let (public_key2, private_key2) = ctx
            .generate_key_pair(
                session,
                &RSA_MECHANISM,
                RSA_PUBLIC_KEY_ATTRIBUTES,
                RSA_PRIVATE_KEY_ATTRIBUTES,
            )
            .unwrap();

        assert_objects(
            ctx,
            session,
            &[public_key1, public_key2, private_key1, private_key2],
        );

        ctx.destroy_object(session, private_key1).unwrap();

        assert_objects(ctx, session, &[public_key2, private_key2]);

        ctx.destroy_object(session, private_key2).unwrap();

        assert_objects(ctx, session, &[]);
    })
}
