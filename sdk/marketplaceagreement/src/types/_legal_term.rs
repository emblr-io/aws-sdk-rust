// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines the list of text agreements proposed to the acceptors. An example is the end user license agreement (EULA).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LegalTerm {
    /// <p>Category of the term being updated.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>List of references to legal resources proposed to the buyers. An example is the EULA.</p>
    pub documents: ::std::option::Option<::std::vec::Vec<crate::types::DocumentItem>>,
}
impl LegalTerm {
    /// <p>Category of the term being updated.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>List of references to legal resources proposed to the buyers. An example is the EULA.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.documents.is_none()`.
    pub fn documents(&self) -> &[crate::types::DocumentItem] {
        self.documents.as_deref().unwrap_or_default()
    }
}
impl LegalTerm {
    /// Creates a new builder-style object to manufacture [`LegalTerm`](crate::types::LegalTerm).
    pub fn builder() -> crate::types::builders::LegalTermBuilder {
        crate::types::builders::LegalTermBuilder::default()
    }
}

/// A builder for [`LegalTerm`](crate::types::LegalTerm).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LegalTermBuilder {
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) documents: ::std::option::Option<::std::vec::Vec<crate::types::DocumentItem>>,
}
impl LegalTermBuilder {
    /// <p>Category of the term being updated.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Category of the term being updated.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Category of the term being updated.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// Appends an item to `documents`.
    ///
    /// To override the contents of this collection use [`set_documents`](Self::set_documents).
    ///
    /// <p>List of references to legal resources proposed to the buyers. An example is the EULA.</p>
    pub fn documents(mut self, input: crate::types::DocumentItem) -> Self {
        let mut v = self.documents.unwrap_or_default();
        v.push(input);
        self.documents = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of references to legal resources proposed to the buyers. An example is the EULA.</p>
    pub fn set_documents(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DocumentItem>>) -> Self {
        self.documents = input;
        self
    }
    /// <p>List of references to legal resources proposed to the buyers. An example is the EULA.</p>
    pub fn get_documents(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DocumentItem>> {
        &self.documents
    }
    /// Consumes the builder and constructs a [`LegalTerm`](crate::types::LegalTerm).
    pub fn build(self) -> crate::types::LegalTerm {
        crate::types::LegalTerm {
            r#type: self.r#type,
            documents: self.documents,
        }
    }
}
