use proc_macro2::{Ident, TokenStream};
use quote::{quote, quote_spanned};
use syn::{
    Type,
    parse::Parser, parse_macro_input, parse_quote, spanned::Spanned, Data, DeriveInput, Field,
    Fields, GenericParam, Generics, Index,
};

#[proc_macro_derive(IntoCRDT)]
pub fn derive_json_crdt(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);

    // Used in the quasi-quotation below as `#name`.
    let ident = input.ident.clone();
    let s = format!("{ident}CRDT");
    let crdt_ident = Ident::new_raw(&*s, input.span());

    // new fields
    match input.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => {
                let new_fields = fields.named.iter().map(|f| {
                    let ident = f.ident.as_ref().unwrap();
                    Field::parse_named
                        .parse2(quote! {
                            #ident: String
                        })
                        .unwrap()
                });

                let expanded = quote! {
                    struct #crdt_ident {
                        #(#new_fields),*
                        // todo
                    }

                    impl IntoCRDT for #ident {
                        type To = #crdt_ident;
                        fn to_crdt(self, keypair: &Ed25519KeyPair, path: Vec<PathSegment>) -> Self::To {
                            // todo
                            unimplemented!()
                        }
                    }

                    impl CRDT for #crdt_ident {
                        type From = #ident;
                        fn apply(&mut self, op: Op<Self::From>) {
                            // todo
                            unimplemented!()
                        }

                        fn view(&self) -> Option<&Self::From> {
                            // todo
                            unimplemented!()
                        } 
                    }

                    impl<'a> BaseCRDT<'a, #crdt_ident> {
                        fn new(doc: #ident, keypair: &'a Ed25519KeyPair) -> Self {
                            let id = keypair.public().0.to_bytes();
                            Self {
                                id,
                                keypair,
                                doc: doc.to_crdt(&keypair, vec![]),
                                path: vec![]
                            }
                        }
                    }
                };

                // Hand the output tokens back to the compiler
                expanded.into()
            }
            _ => {
                return quote! { compile_error!("All fields must be named and initialized"); }
                    .into()
            }
        },
        _ => return quote! { compile_error!("IntoCRDT can only be derived on structs"); }.into(),
    }
}
