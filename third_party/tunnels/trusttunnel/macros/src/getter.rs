use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DataStruct, DeriveInput, Fields};

pub(crate) fn derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let fields = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields
            .named
            .iter()
            .filter_map(|field| field.ident.as_ref().zip(Some(&field.ty)))
            .collect::<Vec<_>>(),
        _ => panic!("`Getter` has to be used only with structs"),
    };

    let funcs = fields.into_iter().fold(quote!(), |stream, (name, ty)| {
        let fn_name = format_ident!("get_{name}");
        quote! {
            #stream
            pub fn #fn_name(&self) -> &#ty {
                &self.#name
            }
        }
    });

    let name = format_ident!("{}", ast.ident);
    let gen = quote! {
        impl #name {
            #funcs
        }
    };
    gen.into()
}
