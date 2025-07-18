// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration information for document attributes. Document attributes are metadata or fields associated with your documents. For example, the company department name associated with each document.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/amazonq/latest/business-use-dg/doc-attributes.html">Understanding document attributes</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DocumentAttributeConfiguration {
    /// <p>The name of the document attribute.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of document attribute.</p>
    pub r#type: ::std::option::Option<crate::types::AttributeType>,
    /// <p>Information about whether the document attribute can be used by an end user to search for information on their web experience.</p>
    pub search: ::std::option::Option<crate::types::Status>,
}
impl DocumentAttributeConfiguration {
    /// <p>The name of the document attribute.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of document attribute.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::AttributeType> {
        self.r#type.as_ref()
    }
    /// <p>Information about whether the document attribute can be used by an end user to search for information on their web experience.</p>
    pub fn search(&self) -> ::std::option::Option<&crate::types::Status> {
        self.search.as_ref()
    }
}
impl DocumentAttributeConfiguration {
    /// Creates a new builder-style object to manufacture [`DocumentAttributeConfiguration`](crate::types::DocumentAttributeConfiguration).
    pub fn builder() -> crate::types::builders::DocumentAttributeConfigurationBuilder {
        crate::types::builders::DocumentAttributeConfigurationBuilder::default()
    }
}

/// A builder for [`DocumentAttributeConfiguration`](crate::types::DocumentAttributeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DocumentAttributeConfigurationBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::AttributeType>,
    pub(crate) search: ::std::option::Option<crate::types::Status>,
}
impl DocumentAttributeConfigurationBuilder {
    /// <p>The name of the document attribute.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the document attribute.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the document attribute.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of document attribute.</p>
    pub fn r#type(mut self, input: crate::types::AttributeType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of document attribute.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::AttributeType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of document attribute.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::AttributeType> {
        &self.r#type
    }
    /// <p>Information about whether the document attribute can be used by an end user to search for information on their web experience.</p>
    pub fn search(mut self, input: crate::types::Status) -> Self {
        self.search = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about whether the document attribute can be used by an end user to search for information on their web experience.</p>
    pub fn set_search(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.search = input;
        self
    }
    /// <p>Information about whether the document attribute can be used by an end user to search for information on their web experience.</p>
    pub fn get_search(&self) -> &::std::option::Option<crate::types::Status> {
        &self.search
    }
    /// Consumes the builder and constructs a [`DocumentAttributeConfiguration`](crate::types::DocumentAttributeConfiguration).
    pub fn build(self) -> crate::types::DocumentAttributeConfiguration {
        crate::types::DocumentAttributeConfiguration {
            name: self.name,
            r#type: self.r#type,
            search: self.search,
        }
    }
}
