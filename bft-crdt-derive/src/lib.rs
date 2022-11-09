use proc_macro::TokenStream as OgTokenStream;
use proc_macro2::{Ident, Span, TokenStream};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{quote, quote_spanned, ToTokens};
use syn::{
    parse::{self, Parser},
    parse_macro_input,
    spanned::Spanned,
    Data, DeriveInput, Field, Fields, GenericParam, ItemStruct, LitStr, Type,
};

fn get_crate_name() -> TokenStream {
    let cr8 = crate_name("bft_json_crdt")
        .ok()
        .unwrap_or(FoundCrate::Itself);
    match cr8 {
        FoundCrate::Itself => quote! { crate },
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            quote! { #ident }
        }
    }
}

#[proc_macro_attribute]
pub fn add_path_field(args: OgTokenStream, input: OgTokenStream) -> OgTokenStream {
    let mut item_struct = parse_macro_input!(input as ItemStruct);
    let crate_name = get_crate_name();
    let _ = parse_macro_input!(args as parse::Nothing);

    if let syn::Fields::Named(ref mut fields) = item_struct.fields {
        fields.named.push(
            Field::parse_named
                .parse2(quote! { path: Vec<#crate_name::op::PathSegment> })
                .unwrap(),
        );
    }

    return quote! {
        #item_struct
    }
    .into();
}

#[proc_macro_derive(CRDT)]
pub fn derive_json_crdt(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);
    let crate_name = get_crate_name();

    // Used in the quasi-quotation below as `#name`.
    let ident = input.ident;

    // ensure only one lifetime
    let mut lt = None;
    let mut num_lt = 0;
    for param in &input.generics.params {
        match param {
            GenericParam::Lifetime(lt_param) => {
                if num_lt >= 1 {
                    return quote_spanned! { lt_param.span() => compile_error!("A struct that derives CRDT can have at most one lifetime") }.into();
                }
                lt = Some(lt_param.lifetime.clone());
                num_lt += 1;
            }
            _ => {}
        }
    }

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    match input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let mut field_impls = vec![];
                let mut ident_literals = vec![];
                let mut ident_strings = vec![];
                for field in &fields.named {
                    let ident = field.ident.as_ref().expect("Failed to get struct field identifier");
                    if ident != "path" {
                        let ty = match &field.ty {
                            Type::Path(t) => t.to_token_stream(),
                            _ => return quote_spanned! { field.span() => compile_error!("Field should be a primitive or struct which implements CRDT") }.into(),
                        };
                        let str_literal = LitStr::new(&*ident.to_string(), ident.span());
                        ident_strings.push(str_literal.clone());
                        ident_literals.push(ident.clone());
                        field_impls.push(quote! {
                            #ident: <#ty as CRDT>::new(
                                keypair,
                                #crate_name::op::join_path(path.clone(), #crate_name::op::PathSegment::Field(#str_literal.to_string()))
                            )
                        });
                    }
                }

                let expanded = quote! {
                    impl #impl_generics #crate_name::json_crdt::CRDT #ty_generics for #ident #ty_generics #where_clause {
                        type Inner = #crate_name::json_crdt::Value;
                        type View = #crate_name::json_crdt::Value;

                        fn apply(&mut self, op: #crate_name::op::Op<Self::Inner>) {
                            // tried to assign to a struct field directly, invalid
                            if self.path.len() >= op.path.len() {
                                return;
                            }

                            let mut idx = 0;
                            for (our_path_segment, op_path_segment) in self.path.iter().zip(op.path.iter()) {
                                let ours = if let #crate_name::op::PathSegment::Field(f) = our_path_segment { Some(f) } else { None };
                                let theirs = if let #crate_name::op::PathSegment::Field(f) = op_path_segment { Some(f) } else { None };
                                if ours != theirs {
                                    return;
                                }
                                idx += 1;
                            }

                            if let #crate_name::op::PathSegment::Field(path_seg) = &op.path[idx] {
                                match &path_seg[..] {
                                    #(#ident_strings => {
                                        self.#ident_literals.apply(op.into());
                                    }),*
                                    _ => {},
                                };
                            };
                        }

                        fn view(&#lt self) -> Self::View {
                            let mut view_map = std::collections::HashMap::new();
                            #(view_map.insert(#ident_strings.to_string(), self.#ident_literals.view().into());)*
                            #crate_name::json_crdt::Value::Object(view_map)
                        }

                        fn new(keypair: &#lt #crate_name::keypair::Ed25519KeyPair, path: Vec<#crate_name::op::PathSegment>) -> Self {
                            Self {
                                path: path.clone(),
                                #(#field_impls),*
                            }
                        }
                    }
                };

                // Hand the output tokens back to the compiler
                expanded.into()
            }
            _ => {
                return quote_spanned! { ident.span() => compile_error!("Cannot derive CRDT on tuple or unit structs"); }
                    .into()
            }
        },
        _ => return quote_spanned! { ident.span() => compile_error!("Cannot derive CRDT on enums or unions"); }.into(),
    }
}
