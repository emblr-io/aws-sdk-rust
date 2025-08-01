// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The document ID and its fields/attributes that are used for a query suggestion, if document fields set to use for query suggestions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SourceDocument {
    /// <p>The identifier of the document used for a query suggestion.</p>
    pub document_id: ::std::option::Option<::std::string::String>,
    /// <p>The document fields/attributes used for a query suggestion.</p>
    pub suggestion_attributes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The additional fields/attributes to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    pub additional_attributes: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>,
}
impl SourceDocument {
    /// <p>The identifier of the document used for a query suggestion.</p>
    pub fn document_id(&self) -> ::std::option::Option<&str> {
        self.document_id.as_deref()
    }
    /// <p>The document fields/attributes used for a query suggestion.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.suggestion_attributes.is_none()`.
    pub fn suggestion_attributes(&self) -> &[::std::string::String] {
        self.suggestion_attributes.as_deref().unwrap_or_default()
    }
    /// <p>The additional fields/attributes to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.additional_attributes.is_none()`.
    pub fn additional_attributes(&self) -> &[crate::types::DocumentAttribute] {
        self.additional_attributes.as_deref().unwrap_or_default()
    }
}
impl SourceDocument {
    /// Creates a new builder-style object to manufacture [`SourceDocument`](crate::types::SourceDocument).
    pub fn builder() -> crate::types::builders::SourceDocumentBuilder {
        crate::types::builders::SourceDocumentBuilder::default()
    }
}

/// A builder for [`SourceDocument`](crate::types::SourceDocument).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceDocumentBuilder {
    pub(crate) document_id: ::std::option::Option<::std::string::String>,
    pub(crate) suggestion_attributes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) additional_attributes: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>,
}
impl SourceDocumentBuilder {
    /// <p>The identifier of the document used for a query suggestion.</p>
    pub fn document_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the document used for a query suggestion.</p>
    pub fn set_document_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_id = input;
        self
    }
    /// <p>The identifier of the document used for a query suggestion.</p>
    pub fn get_document_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_id
    }
    /// Appends an item to `suggestion_attributes`.
    ///
    /// To override the contents of this collection use [`set_suggestion_attributes`](Self::set_suggestion_attributes).
    ///
    /// <p>The document fields/attributes used for a query suggestion.</p>
    pub fn suggestion_attributes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.suggestion_attributes.unwrap_or_default();
        v.push(input.into());
        self.suggestion_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The document fields/attributes used for a query suggestion.</p>
    pub fn set_suggestion_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.suggestion_attributes = input;
        self
    }
    /// <p>The document fields/attributes used for a query suggestion.</p>
    pub fn get_suggestion_attributes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.suggestion_attributes
    }
    /// Appends an item to `additional_attributes`.
    ///
    /// To override the contents of this collection use [`set_additional_attributes`](Self::set_additional_attributes).
    ///
    /// <p>The additional fields/attributes to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    pub fn additional_attributes(mut self, input: crate::types::DocumentAttribute) -> Self {
        let mut v = self.additional_attributes.unwrap_or_default();
        v.push(input);
        self.additional_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The additional fields/attributes to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    pub fn set_additional_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>>) -> Self {
        self.additional_attributes = input;
        self
    }
    /// <p>The additional fields/attributes to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    pub fn get_additional_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DocumentAttribute>> {
        &self.additional_attributes
    }
    /// Consumes the builder and constructs a [`SourceDocument`](crate::types::SourceDocument).
    pub fn build(self) -> crate::types::SourceDocument {
        crate::types::SourceDocument {
            document_id: self.document_id,
            suggestion_attributes: self.suggestion_attributes,
            additional_attributes: self.additional_attributes,
        }
    }
}
