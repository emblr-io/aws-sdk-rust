// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a document that matches the search request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Hit {
    /// <p>The document ID of a document that matches the search request.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The fields returned from a document that matches the search request.</p>
    pub fields: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    /// <p>The expressions returned from a document that matches the search request.</p>
    pub exprs: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The highlights returned from a document that matches the search request.</p>
    pub highlights: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl Hit {
    /// <p>The document ID of a document that matches the search request.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The fields returned from a document that matches the search request.</p>
    pub fn fields(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        self.fields.as_ref()
    }
    /// <p>The expressions returned from a document that matches the search request.</p>
    pub fn exprs(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.exprs.as_ref()
    }
    /// <p>The highlights returned from a document that matches the search request.</p>
    pub fn highlights(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.highlights.as_ref()
    }
}
impl Hit {
    /// Creates a new builder-style object to manufacture [`Hit`](crate::types::Hit).
    pub fn builder() -> crate::types::builders::HitBuilder {
        crate::types::builders::HitBuilder::default()
    }
}

/// A builder for [`Hit`](crate::types::Hit).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HitBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) fields: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    pub(crate) exprs: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) highlights: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl HitBuilder {
    /// <p>The document ID of a document that matches the search request.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The document ID of a document that matches the search request.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The document ID of a document that matches the search request.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Adds a key-value pair to `fields`.
    ///
    /// To override the contents of this collection use [`set_fields`](Self::set_fields).
    ///
    /// <p>The fields returned from a document that matches the search request.</p>
    pub fn fields(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.fields.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.fields = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The fields returned from a document that matches the search request.</p>
    pub fn set_fields(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.fields = input;
        self
    }
    /// <p>The fields returned from a document that matches the search request.</p>
    pub fn get_fields(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.fields
    }
    /// Adds a key-value pair to `exprs`.
    ///
    /// To override the contents of this collection use [`set_exprs`](Self::set_exprs).
    ///
    /// <p>The expressions returned from a document that matches the search request.</p>
    pub fn exprs(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.exprs.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.exprs = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The expressions returned from a document that matches the search request.</p>
    pub fn set_exprs(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.exprs = input;
        self
    }
    /// <p>The expressions returned from a document that matches the search request.</p>
    pub fn get_exprs(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.exprs
    }
    /// Adds a key-value pair to `highlights`.
    ///
    /// To override the contents of this collection use [`set_highlights`](Self::set_highlights).
    ///
    /// <p>The highlights returned from a document that matches the search request.</p>
    pub fn highlights(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.highlights.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.highlights = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The highlights returned from a document that matches the search request.</p>
    pub fn set_highlights(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.highlights = input;
        self
    }
    /// <p>The highlights returned from a document that matches the search request.</p>
    pub fn get_highlights(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.highlights
    }
    /// Consumes the builder and constructs a [`Hit`](crate::types::Hit).
    pub fn build(self) -> crate::types::Hit {
        crate::types::Hit {
            id: self.id,
            fields: self.fields,
            exprs: self.exprs,
            highlights: self.highlights,
        }
    }
}
