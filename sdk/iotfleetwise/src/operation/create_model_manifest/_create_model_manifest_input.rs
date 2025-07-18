// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateModelManifestInput {
    /// <p>The name of the vehicle model to create.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A brief description of the vehicle model.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of nodes, which are a general abstraction of signals.</p>
    pub nodes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) of a signal catalog.</p>
    pub signal_catalog_arn: ::std::option::Option<::std::string::String>,
    /// <p>Metadata that can be used to manage the vehicle model.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateModelManifestInput {
    /// <p>The name of the vehicle model to create.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A brief description of the vehicle model.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A list of nodes, which are a general abstraction of signals.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.nodes.is_none()`.
    pub fn nodes(&self) -> &[::std::string::String] {
        self.nodes.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) of a signal catalog.</p>
    pub fn signal_catalog_arn(&self) -> ::std::option::Option<&str> {
        self.signal_catalog_arn.as_deref()
    }
    /// <p>Metadata that can be used to manage the vehicle model.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateModelManifestInput {
    /// Creates a new builder-style object to manufacture [`CreateModelManifestInput`](crate::operation::create_model_manifest::CreateModelManifestInput).
    pub fn builder() -> crate::operation::create_model_manifest::builders::CreateModelManifestInputBuilder {
        crate::operation::create_model_manifest::builders::CreateModelManifestInputBuilder::default()
    }
}

/// A builder for [`CreateModelManifestInput`](crate::operation::create_model_manifest::CreateModelManifestInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateModelManifestInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) nodes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) signal_catalog_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateModelManifestInputBuilder {
    /// <p>The name of the vehicle model to create.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the vehicle model to create.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the vehicle model to create.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A brief description of the vehicle model.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A brief description of the vehicle model.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A brief description of the vehicle model.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `nodes`.
    ///
    /// To override the contents of this collection use [`set_nodes`](Self::set_nodes).
    ///
    /// <p>A list of nodes, which are a general abstraction of signals.</p>
    pub fn nodes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.nodes.unwrap_or_default();
        v.push(input.into());
        self.nodes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of nodes, which are a general abstraction of signals.</p>
    pub fn set_nodes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.nodes = input;
        self
    }
    /// <p>A list of nodes, which are a general abstraction of signals.</p>
    pub fn get_nodes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.nodes
    }
    /// <p>The Amazon Resource Name (ARN) of a signal catalog.</p>
    /// This field is required.
    pub fn signal_catalog_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.signal_catalog_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a signal catalog.</p>
    pub fn set_signal_catalog_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.signal_catalog_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a signal catalog.</p>
    pub fn get_signal_catalog_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.signal_catalog_arn
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata that can be used to manage the vehicle model.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata that can be used to manage the vehicle model.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata that can be used to manage the vehicle model.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateModelManifestInput`](crate::operation::create_model_manifest::CreateModelManifestInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_model_manifest::CreateModelManifestInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_model_manifest::CreateModelManifestInput {
            name: self.name,
            description: self.description,
            nodes: self.nodes,
            signal_catalog_arn: self.signal_catalog_arn,
            tags: self.tags,
        })
    }
}
