use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::parse::Parser;
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Field, Fields, GenericParam, Generics, Index,
};

#[proc_macro_derive(IntoCRDT)]
pub fn derive_json_crdt(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let mut input = parse_macro_input!(input as DeriveInput);

    // Used in the quasi-quotation below as `#name`.
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // make sure:
    // - each field is
    //  - private
    //  - is of type (then add appropriate $ident() fn)
    //   - Terminal -> wrap in LWW
    //   - Vec<Terminal | JsonCRDT> -> 
    //   - HashMap<Terminal | JsonCRDT> -> literally just return the crdt
    // then implement:
    // - init_crdt(&mut self) -> ConcreteCRDT<'a, #name>
    // - apply(&mut self, op: Op<Terminal>)
    // - view(&self) -> #name
    add_new_fields(&mut input.data);

    let expanded = quote! {
        // The generated impl.
        impl #impl_generics super::IntoCRDT<'_, #name> for #name #ty_generics #where_clause {
            // idents
        }

        impl #impl_generics super::CRDT<#name> for #name #ty_generics #where_clause {
            // idents
        }
    };

    // Hand the output tokens back to the compiler.
    proc_macro::TokenStream::from(expanded)
}

// Generate an expression to sum up the heap size of each field.
fn add_new_fields(data: &mut Data) -> Option<TokenStream> {
    match *data {
        Data::Struct(ref mut data) => {
            if let Fields::Named(fields) = &mut data.fields {
                fields
                    .named
                    .push(Field::parse_named.parse2(quote! { pub a: String }).unwrap());
            }
            None
        }
        Data::Enum(ref data) => Some(quote_spanned! {
            data.enum_token.span => compile_error!("`JsonCRDT` can only be derived on structs!");

        }),
        Data::Union(ref data) => Some(quote_spanned! {
            data.union_token.span => compile_error!("`JsonCRDT` can only be derived on structs!");

        }),
    }
}
