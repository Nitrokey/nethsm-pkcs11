#![cfg(feature = "pkcs11-full-tests")]

pub mod tools;

use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::Session,
};

struct KeyPair {
    public: ObjectHandle,
    private: ObjectHandle,
}

impl KeyPair {
    fn destroy(&self, session: &Session) {
        session.destroy_object(self.private).unwrap();
    }
}

fn generate_rsa_key(session: &Session) -> KeyPair {
    let pub_key_template = &[
        Attribute::Verify(true),
        Attribute::ModulusBits(2048.into()),
        Attribute::Token(false),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
    ];
    let priv_key_template = &[Attribute::Sign(true), Attribute::Token(false)];
    let (public, private) = session
        .generate_key_pair(&Mechanism::RsaPkcs, pub_key_template, priv_key_template)
        .unwrap();
    KeyPair { public, private }
}

fn get_id_label(session: &Session, object: ObjectHandle) -> (String, String) {
    // TODO: ID should be Vec<u8>, not String
    let attributes = session
        .get_attributes(object, &[AttributeType::Id, AttributeType::Label])
        .unwrap();
    assert_eq!(attributes.len(), 2);

    let Attribute::Id(id) = &attributes[0] else {
        panic!("Unexpected attribute returned for ID: {:?}", attributes[0]);
    };
    let Attribute::Label(label) = &attributes[1] else {
        panic!(
            "Unexpected attribute returned for label: {:?}",
            attributes[1]
        );
    };
    let id = str::from_utf8(id).unwrap().to_owned();
    let label = str::from_utf8(label).unwrap().to_owned();
    (id, label)
}

fn assert_objects(session: &Session, expected: &[ObjectHandle]) {
    let mut objects: Vec<_> = session
        .find_objects(&[])
        .unwrap()
        .into_iter()
        .map(|o| o.handle())
        .collect();
    let mut expected_objects: Vec<_> = expected.iter().map(ObjectHandle::handle).collect();
    objects.sort();
    expected_objects.sort();
    assert_eq!(objects, expected_objects);
}

#[test_log::test]
fn set_attribute_value() {
    tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();
        let key = generate_rsa_key(&session);

        let (public_id, public_label) = get_id_label(&session, key.public);
        println!("public key: id = {public_id}, label = {public_label}");
        let (private_id, private_label) = get_id_label(&session, key.private);
        println!("private key: id = {private_id}, label = {private_label}");

        let new_id = "mynewkeyid";
        session
            .update_attributes(key.private, &[Attribute::Id(new_id.as_bytes().to_owned())])
            .unwrap();

        let (public_id, public_label) = get_id_label(&session, key.public);
        let (private_id, private_label) = get_id_label(&session, key.private);

        assert_eq!(&public_id, new_id);
        assert_eq!(&public_label, "");
        assert_eq!(&private_id, new_id);
        assert_eq!(&private_label, "");

        key.destroy(&session);
    })
}

#[test_log::test]
fn delete() {
    tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();

        let key1 = generate_rsa_key(&session);
        let key2 = generate_rsa_key(&session);
        assert_objects(
            &session,
            &[key1.public, key1.private, key2.public, key2.private],
        );

        key1.destroy(&session);
        assert_objects(&session, &[key2.public, key2.private]);

        key2.destroy(&session);
        assert_objects(&session, &[]);
    })
}
