use macros::RuntimeDoc;

#[test]
fn slashed() {
    /// Trololo
    #[allow(dead_code)]
    #[derive(RuntimeDoc)]
    struct Foo {
        /// Haha
        pub x: u32,
    }

    assert_eq!(Foo::doc(), "Trololo");
    assert_eq!(Foo::doc_x(), "Haha");
}

#[test]
fn doc_attr() {
    #[doc = "Trololo"]
    #[allow(dead_code)]
    #[derive(RuntimeDoc)]
    struct Foo {
        #[doc = "Haha"]
        pub x: u32,
    }

    assert_eq!(Foo::doc(), "Trololo");
    assert_eq!(Foo::doc_x(), "Haha");
}

#[test]
fn mixed() {
    /// - How much watch?
    #[doc = "- Six watch"]
    #[allow(dead_code)]
    #[derive(RuntimeDoc)]
    struct Foo {
        /// - Such much?
        #[doc = "- For whom how"]
        pub x: u32,
    }

    assert_eq!(
        Foo::doc(),
        r#"- How much watch?
- Six watch"#
    );
    assert_eq!(
        Foo::doc_x(),
        r#"- Such much?
- For whom how"#
    );
}
