// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSignalCatalogInput {
    /// <p>The name of the signal catalog to create.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A brief description of the signal catalog.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of information about nodes, which are a general abstraction of signals. For more information, see the API data type.</p>
    pub nodes: ::std::option::Option<::std::vec::Vec<crate::types::Node>>,
    /// <p>Metadata that can be used to manage the signal catalog.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateSignalCatalogInput {
    /// <p>The name of the signal catalog to create.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A brief description of the signal catalog.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A list of information about nodes, which are a general abstraction of signals. For more information, see the API data type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.nodes.is_none()`.
    pub fn nodes(&self) -> &[crate::types::Node] {
        self.nodes.as_deref().unwrap_or_default()
    }
    /// <p>Metadata that can be used to manage the signal catalog.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateSignalCatalogInput {
    /// Creates a new builder-style object to manufacture [`CreateSignalCatalogInput`](crate::operation::create_signal_catalog::CreateSignalCatalogInput).
    pub fn builder() -> crate::operation::create_signal_catalog::builders::CreateSignalCatalogInputBuilder {
        crate::operation::create_signal_catalog::builders::CreateSignalCatalogInputBuilder::default()
    }
}

/// A builder for [`CreateSignalCatalogInput`](crate::operation::create_signal_catalog::CreateSignalCatalogInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSignalCatalogInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) nodes: ::std::option::Option<::std::vec::Vec<crate::types::Node>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateSignalCatalogInputBuilder {
    /// <p>The name of the signal catalog to create.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the signal catalog to create.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the signal catalog to create.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A brief description of the signal catalog.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A brief description of the signal catalog.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A brief description of the signal catalog.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `nodes`.
    ///
    /// To override the contents of this collection use [`set_nodes`](Self::set_nodes).
    ///
    /// <p>A list of information about nodes, which are a general abstraction of signals. For more information, see the API data type.</p>
    pub fn nodes(mut self, input: crate::types::Node) -> Self {
        let mut v = self.nodes.unwrap_or_default();
        v.push(input);
        self.nodes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of information about nodes, which are a general abstraction of signals. For more information, see the API data type.</p>
    pub fn set_nodes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Node>>) -> Self {
        self.nodes = input;
        self
    }
    /// <p>A list of information about nodes, which are a general abstraction of signals. For more information, see the API data type.</p>
    pub fn get_nodes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Node>> {
        &self.nodes
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata that can be used to manage the signal catalog.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata that can be used to manage the signal catalog.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata that can be used to manage the signal catalog.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateSignalCatalogInput`](crate::operation::create_signal_catalog::CreateSignalCatalogInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_signal_catalog::CreateSignalCatalogInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_signal_catalog::CreateSignalCatalogInput {
            name: self.name,
            description: self.description,
            nodes: self.nodes,
            tags: self.tags,
        })
    }
}
