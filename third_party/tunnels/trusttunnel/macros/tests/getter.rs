use macros::Getter;

#[test]
fn test() {
    #[derive(Getter)]
    struct Foo {
        x: usize,
    }

    assert_eq!(Foo { x: 42 }.get_x(), &42);
}
