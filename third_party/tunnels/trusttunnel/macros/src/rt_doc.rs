use proc_macro::TokenStream;
use quote::{format_ident, quote};
use std::iter;
use syn::{Attribute, Data, DataEnum, DataStruct, DeriveInput, Fields, Lit, Meta, MetaNameValue};

#[cfg(target_family = "unix")]
const OS_LINE_ENDING: &str = "\n";
#[cfg(target_family = "windows")]
const OS_LINE_ENDING: &str = "\r\n";

pub(crate) fn derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let docs = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields
            .named
            .iter()
            .filter_map(|field| {
                field
                    .ident
                    .clone()
                    .zip(Some(collect_docs(field.attrs.iter())))
            })
            .collect::<Vec<_>>(),
        Data::Struct(_) => Default::default(),
        Data::Enum(DataEnum { variants, .. }) => variants
            .iter()
            .map(|variant| {
                (
                    format_ident!("{}", variant.ident.to_string().to_lowercase()),
                    collect_docs(variant.attrs.iter()),
                )
            })
            .collect::<Vec<_>>(),
        _ => panic!("`RuntimeDoc` has to be used only with structs or enums"),
    };

    let funcs = iter::once((None, collect_docs(ast.attrs.iter())))
        .chain(docs.into_iter().map(|(ident, doc)| (Some(ident), doc)))
        .fold(quote!(), |stream, (name, doc)| {
            if doc.is_empty() {
                return stream;
            }

            let name = match name {
                Some(x) => format_ident!("doc_{x}"),
                None => format_ident!("doc"),
            };
            quote! {
                #stream
                pub fn #name() -> &'static str {
                    #doc
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

fn collect_docs<'a, I>(attrs: I) -> String
where
    I: Iterator<Item = &'a Attribute>,
{
    attrs
        .filter_map(|attr| attr.parse_meta().ok())
        .filter(|meta| meta.path().is_ident("doc"))
        .filter_map(|meta| match meta {
            Meta::NameValue(MetaNameValue {
                lit: Lit::Str(lit), ..
            }) => Some(lit.value().trim().to_string()),
            _ => None,
        })
        .filter(|doc| !doc.is_empty())
        .collect::<Vec<_>>()
        .join(OS_LINE_ENDING)
}
