#![cfg(feature = "pkcs11-full-tests")]

pub mod tools;

use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::Session,
};
use cryptoki_sys::CK_OBJECT_CLASS;

#[derive(Clone, Debug, PartialEq)]
struct Object {
    id: String,
    label: String,
    class: ObjectClass,
}

impl Object {
    fn into_tuple(self) -> (String, String, CK_OBJECT_CLASS) {
        (self.id, self.label, self.class.into())
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct KeyPair<T> {
    public: T,
    private: T,
}

impl KeyPair<Object> {
    fn destroy(&self, session: &Session) {
        let objects = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(self.private.id.clone().into_bytes()),
            ])
            .unwrap();
        assert_eq!(objects.len(), 1);
        session.destroy_object(objects[0]).unwrap();
    }
}

impl KeyPair<ObjectHandle> {
    fn get_objects(&self, session: &Session) -> KeyPair<Object> {
        let public = get_object(session, self.public);
        let private = get_object(session, self.private);
        println!(
            "Fetched objects for key pair: {} = {public:?}, {} = {private:?}",
            self.public, self.private
        );
        assert_eq!(public.class, ObjectClass::PUBLIC_KEY);
        assert_eq!(private.class, ObjectClass::PRIVATE_KEY);
        KeyPair { public, private }
    }

    fn destroy(&self, session: &Session) {
        session.destroy_object(self.private).unwrap();
    }
}

fn generate_rsa_key(session: &Session, label: Option<&str>) -> KeyPair<ObjectHandle> {
    let pub_key_template = &[
        Attribute::Verify(true),
        Attribute::ModulusBits(2048.into()),
        Attribute::Token(false),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
    ];
    let mut priv_key_template = vec![Attribute::Sign(true), Attribute::Token(false)];
    if let Some(label) = label {
        priv_key_template.push(Attribute::Label(label.as_bytes().to_owned()));
    }
    let (public, private) = session
        .generate_key_pair(&Mechanism::RsaPkcs, pub_key_template, &priv_key_template)
        .unwrap();
    KeyPair { public, private }
}

fn get_object(session: &Session, object: ObjectHandle) -> Object {
    let attributes = session
        .get_attributes(
            object,
            &[
                AttributeType::Id,
                AttributeType::Label,
                AttributeType::Class,
            ],
        )
        .unwrap();
    assert_eq!(attributes.len(), 3);

    let Attribute::Id(id) = &attributes[0] else {
        panic!("Unexpected attribute returned for ID: {:?}", attributes[0]);
    };
    let Attribute::Label(label) = &attributes[1] else {
        panic!(
            "Unexpected attribute returned for label: {:?}",
            attributes[1]
        );
    };
    let Attribute::Class(class) = &attributes[2] else {
        panic!(
            "Unexpected attribute returned for class: {:?}",
            attributes[2]
        );
    };
    let id = str::from_utf8(id).unwrap().to_owned();
    let label = str::from_utf8(label).unwrap().to_owned();
    Object {
        id,
        label,
        class: *class,
    }
}

fn get_objects(session: &Session, objects: &[ObjectHandle]) -> Vec<Object> {
    let mut result = Vec::new();
    for object in objects {
        result.push(get_object(session, *object));
    }
    result
}

fn find_objects(session: &Session, attributes: &[Attribute]) -> Vec<Object> {
    let objects = session.find_objects(attributes).unwrap();
    get_objects(session, &objects)
}

fn assert_object_handles_eq(
    actual: impl IntoIterator<Item = ObjectHandle>,
    expected: &[KeyPair<ObjectHandle>],
) {
    let mut actual_objects: Vec<_> = actual.into_iter().map(|o| o.handle()).collect();
    let mut expected_objects: Vec<_> = expected
        .iter()
        .flat_map(|k| [k.private, k.public])
        .map(|o| o.handle())
        .collect();
    actual_objects.sort();
    expected_objects.sort();
    assert_eq!(actual_objects, expected_objects);
}

fn assert_objects_eq(actual: impl IntoIterator<Item = Object>, expected: &[KeyPair<Object>]) {
    let mut actual_objects: Vec<_> = actual.into_iter().map(|o| o.into_tuple()).collect();
    let mut expected_objects: Vec<_> = expected
        .iter()
        .flat_map(|k| [k.private.clone(), k.public.clone()])
        .map(|o| o.into_tuple())
        .collect();
    actual_objects.sort();
    expected_objects.sort();
    assert_eq!(actual_objects, expected_objects);
}

#[test_log::test]
fn set_attribute_value_id() {
    tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();
        let key = generate_rsa_key(&session, None);

        let mut old_objects = key.get_objects(&session);

        let new_id = "mynewkeyid";
        session
            .update_attributes(key.private, &[Attribute::Id(new_id.as_bytes().to_owned())])
            .unwrap();
        let new_objects = key.get_objects(&session);
        key.destroy(&session);

        old_objects.private.id = new_id.to_owned();
        old_objects.public.id = new_id.to_owned();
        assert_eq!(old_objects, new_objects);
    })
}

#[test_log::test]
fn set_attribute_value_label() {
    let label1 = "label1";
    let label2 = "label2";

    tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();
        let key = generate_rsa_key(&session, Some(label1));

        let mut old_objects = key.get_objects(&session);

        session
            .update_attributes(
                key.private,
                &[Attribute::Label(label2.as_bytes().to_owned())],
            )
            .unwrap();
        let new_objects = key.get_objects(&session);

        old_objects.private.label = label2.to_owned();
        old_objects.public.label = label2.to_owned();
        assert_eq!(old_objects, new_objects);

        let objects = find_objects(&session, &[Attribute::Label(label2.as_bytes().to_owned())]);
        assert_objects_eq(objects, &[old_objects.clone()]);

        session
            .update_attributes(key.private, &[Attribute::Label(Vec::new())])
            .unwrap();
        let new_objects = key.get_objects(&session);

        old_objects.private.label = String::new();
        old_objects.public.label = String::new();
        assert_eq!(old_objects, new_objects);

        key.destroy(&session);
    })
}

#[test_log::test]
fn set_attribute_value_id_label() {
    let label1 = "label1";
    let label2 = "label2";

    tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();
        let key = generate_rsa_key(&session, Some(label1));

        let mut old_objects = key.get_objects(&session);

        let new_id = "mynewkeyid";
        session
            .update_attributes(
                key.private,
                &[
                    Attribute::Label(label2.as_bytes().to_owned()),
                    Attribute::Id(new_id.as_bytes().to_owned()),
                ],
            )
            .unwrap();
        let new_objects = key.get_objects(&session);

        old_objects.private.id = new_id.to_owned();
        old_objects.public.id = new_id.to_owned();
        old_objects.private.label = label2.to_owned();
        old_objects.public.label = label2.to_owned();
        assert_eq!(old_objects, new_objects);

        let objects = find_objects(&session, &[Attribute::Label(label2.as_bytes().to_owned())]);
        assert_objects_eq(objects, &[old_objects.clone()]);

        let objects = find_objects(&session, &[Attribute::Id(new_id.as_bytes().to_owned())]);
        assert_objects_eq(objects, &[old_objects.clone()]);

        key.destroy(&session);
    })
}

#[test_log::test]
fn delete() {
    tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();

        let key1 = generate_rsa_key(&session, None);
        let key2 = generate_rsa_key(&session, None);
        let objects = session.find_objects(&[]).unwrap();
        assert_object_handles_eq(objects, &[key1, key2]);

        key1.destroy(&session);
        let objects = session.find_objects(&[]).unwrap();
        assert_object_handles_eq(objects, &[key2]);

        key2.destroy(&session);
        let objects = session.find_objects(&[]).unwrap();
        assert_object_handles_eq(objects, &[]);
    })
}

#[test_log::test]
fn generate_no_label() {
    tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();
        let key = generate_rsa_key(&session, None);
        let objects = key.get_objects(&session);
        key.destroy(&session);

        assert_eq!(objects.public.label, "");
        assert_eq!(objects.private.label, "");
    })
}

#[test_log::test]
fn generate_label() {
    tools::run_test(|pkcs11, slot| {
        let label = "testlabel123";

        let session = pkcs11.open_rw_session(slot).unwrap();
        let key = generate_rsa_key(&session, Some(label));
        let objects = key.get_objects(&session);
        key.destroy(&session);

        assert_eq!(objects.public.label, label);
        assert_eq!(objects.private.label, label);
    })
}

#[test_log::test]
fn generate_empty_label() {
    tools::run_test(|pkcs11, slot| {
        let label = "";

        let session = pkcs11.open_rw_session(slot).unwrap();
        let key = generate_rsa_key(&session, Some(label));
        let objects = key.get_objects(&session);
        key.destroy(&session);

        assert_eq!(objects.public.label, label);
        assert_eq!(objects.private.label, label);
    })
}

#[test_log::test]
fn list_by_label() {
    // TODO: add certificates
    // TODO: filter by object type

    let label1 = "label1";
    let label2 = "label2";
    let label3 = "label3";

    let all_objects = tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();
        [None, Some(label1), Some(label1), Some(label2)]
            .map(|label| generate_rsa_key(&session, label).get_objects(&session))
    });
    let [objects1, objects2, objects3, objects4] = all_objects.clone();

    let labels = [label1, label2, label3, ""];
    let ids: &[Option<&str>] = &[
        Some(&all_objects[0].private.id),
        Some(&all_objects[1].private.id),
        Some(&all_objects[3].private.id),
        Some("test123"),
        None,
    ];

    for cache in [true, false] {
        for label in labels {
            for id in ids {
                println!();
                println!();
                println!("Running with cache = {cache}, label = {label:?}, id = {id:?}");

                tools::run_test(|pkcs11, slot| {
                    let session = pkcs11.open_rw_session(slot).unwrap();

                    if cache {
                        let objects = find_objects(&session, &[]);
                        assert_objects_eq(objects, &all_objects);
                    }

                    let mut attributes = vec![Attribute::Label(label.as_bytes().to_owned())];
                    if let Some(id) = id {
                        attributes.push(Attribute::Id(id.as_bytes().to_owned()));
                    }
                    let objects = find_objects(&session, &attributes);
                    let expected: Vec<_> = all_objects
                        .iter()
                        .filter(|o| label.is_empty() || o.private.label == label)
                        .filter(|o| id.map(|id| o.private.id == id).unwrap_or(true))
                        .cloned()
                        .collect();
                    assert_objects_eq(objects, &expected)
                })
            }
        }
    }

    tools::run_test(|pkcs11, slot| {
        let session = pkcs11.open_rw_session(slot).unwrap();
        for objects in [objects1, objects2, objects3, objects4] {
            objects.destroy(&session);
        }
    });
}
