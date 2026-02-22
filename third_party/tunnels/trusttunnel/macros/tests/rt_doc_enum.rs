use macros::RuntimeDoc;

#[test]
fn slashed() {
    /// Trololo
    #[allow(dead_code)]
    #[derive(RuntimeDoc)]
    enum Foo {
        /// Haha
        Bar,
        /// Hehe
        Baz,
    }

    assert_eq!(Foo::doc(), "Trololo");
    assert_eq!(Foo::doc_bar(), "Haha");
    assert_eq!(Foo::doc_baz(), "Hehe");
}

#[test]
fn doc_attr() {
    #[doc = "Trololo"]
    #[allow(dead_code)]
    #[derive(RuntimeDoc)]
    enum Foo {
        #[doc = "Haha"]
        Bar,
        #[doc = "Hehe"]
        Baz,
    }

    assert_eq!(Foo::doc(), "Trololo");
    assert_eq!(Foo::doc_bar(), "Haha");
    assert_eq!(Foo::doc_baz(), "Hehe");
}

#[test]
fn mixed() {
    /// - How much watch?
    #[doc = "- Six watch"]
    #[allow(dead_code)]
    #[derive(RuntimeDoc)]
    enum Foo {
        /// - Such much?
        #[doc = "- For whom how"]
        Bar,
        /// - MGIMO finished?
        #[doc = "- Ask"]
        Baz,
    }

    assert_eq!(
        Foo::doc(),
        r#"- How much watch?
- Six watch"#
    );
    assert_eq!(
        Foo::doc_bar(),
        r#"- Such much?
- For whom how"#
    );
    assert_eq!(
        Foo::doc_baz(),
        r#"- MGIMO finished?
- Ask"#
    );
}
