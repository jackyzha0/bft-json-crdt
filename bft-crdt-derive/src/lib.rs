use proc_macro::TokenStream as OgTokenStream;
use proc_macro2::{Ident, Span, TokenStream};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{quote, quote_spanned, ToTokens};
use syn::{
    parse::{self, Parser},
    parse_macro_input,
    spanned::Spanned,
    Data, DeriveInput, Field, Fields, ItemStruct, LitStr, Type
};

fn get_crate_name() -> TokenStream {
    let cr8 = crate_name("bft-json-crdt")
        .unwrap_or(FoundCrate::Itself);
    match cr8 {
        FoundCrate::Itself => quote! { ::bft_json_crdt },
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            quote! { ::#ident }
        }
    }
}

// creates a keypair and path var on a given struct
#[proc_macro_attribute]
pub fn add_crdt_fields(args: OgTokenStream, input: OgTokenStream) -> OgTokenStream {
    let mut input = parse_macro_input!(input as ItemStruct);
    let crate_name = get_crate_name();
    let _ = parse_macro_input!(args as parse::Nothing);

    if let syn::Fields::Named(ref mut fields) = input.fields {
        fields.named.push(
            Field::parse_named
                .parse2(quote! { path: Vec<#crate_name::op::PathSegment> })
                .unwrap(),
        );
        fields.named.push(
            Field::parse_named
                .parse2(quote! { id: #crate_name::keypair::AuthorID })
                .unwrap(),
        );
    }

    return quote! {
        #input
    }
    .into();
}

#[proc_macro_derive(CRDT)]
pub fn derive_json_crdt(input: OgTokenStream) -> OgTokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);
    let crate_name = get_crate_name();

    // Used in the quasi-quotation below as `#name`.
    let ident = input.ident;
    let ident_str = LitStr::new(&*ident.to_string(), ident.span());

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    match input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let mut field_impls = vec![];
                let mut ident_literals = vec![];
                let mut ident_strings = vec![];
                let mut tys = vec![];
                for field in &fields.named {
                    let ident = field.ident.as_ref().expect("Failed to get struct field identifier");
                    if ident != "path" && ident != "id" {
                        let ty = match &field.ty {
                            Type::Path(t) => t.to_token_stream(),
                            _ => return quote_spanned! { field.span() => compile_error!("Field should be a primitive or struct which implements CRDT") }.into(),
                        };
                        let str_literal = LitStr::new(&*ident.to_string(), ident.span());
                        ident_strings.push(str_literal.clone());
                        ident_literals.push(ident.clone());
                        tys.push(ty.clone());
                        field_impls.push(quote! {
                            #ident: <#ty as CRDT>::new(
                                id,
                                #crate_name::op::join_path(path.clone(), #crate_name::op::PathSegment::Field(#str_literal.to_string()))
                            )
                        });
                    }
                }

                let expanded = quote! {
                    impl #impl_generics #crate_name::json_crdt::CRDTTerminalFrom<#crate_name::json_crdt::Value> for #ident #ty_generics #where_clause {
                        fn terminal_from(value: #crate_name::json_crdt::Value, id: #crate_name::keypair::AuthorID, path: Vec<#crate_name::op::PathSegment>) -> Result<Self, String> {
                            if let #crate_name::json_crdt::Value::Object(mut obj) = value {
                                Ok(#ident {
                                    path: path.clone(),
                                    id,
                                    #(#ident_literals: obj.remove(#ident_strings)
                                        .unwrap()
                                        .into_terminal(
                                            id,
                                            #crate_name::op::join_path(path.clone(), #crate_name::op::PathSegment::Field(#ident_strings.to_string()))
                                        )
                                        .unwrap()
                                    ),*
                                })
                            } else {
                                Err(format!("failed to convert {:?} -> {}<T>", value, #ident_str.to_string()))
                            }  
                        }
                    }

                    impl #impl_generics std::fmt::Debug for #ident #ty_generics #where_clause {
                        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            let mut fields = Vec::new();
                            #(fields.push(format!("{}", #ident_strings.to_string()));)*
                            write!(f, "{{ {:?} }}", fields.join(", "))
                        }
                    } 

                    impl #impl_generics #crate_name::json_crdt::CRDT for #ident #ty_generics #where_clause {
                        type Inner = #crate_name::json_crdt::Value;
                        type View = #crate_name::json_crdt::Value;

                        fn apply(&mut self, op: #crate_name::op::Op<Self::Inner>) {
                            // tried to assign to a struct field directly, invalid
                            let path = op.path.clone();
                            if self.path.len() >= path.len() {
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
                                        self.#ident_literals.apply(op.into(self.id, path));
                                    }),*
                                    _ => {},
                                };
                            };
                        }

                        fn view(&self) -> Self::View {
                            let mut view_map = std::collections::HashMap::new();
                            #(view_map.insert(#ident_strings.to_string(), self.#ident_literals.view().into());)*
                            #crate_name::json_crdt::Value::Object(view_map)
                        }

                        fn new(id: #crate_name::keypair::AuthorID, path: Vec<#crate_name::op::PathSegment>) -> Self {
                            Self {
                                path: path.clone(),
                                id,
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
