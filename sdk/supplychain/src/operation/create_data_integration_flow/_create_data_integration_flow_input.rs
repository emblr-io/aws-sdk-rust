// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request parameters for CreateDataIntegrationFlow.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDataIntegrationFlowInput {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>Name of the DataIntegrationFlow.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The source configurations for DataIntegrationFlow.</p>
    pub sources: ::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationFlowSource>>,
    /// <p>The transformation configurations for DataIntegrationFlow.</p>
    pub transformation: ::std::option::Option<crate::types::DataIntegrationFlowTransformation>,
    /// <p>The target configurations for DataIntegrationFlow.</p>
    pub target: ::std::option::Option<crate::types::DataIntegrationFlowTarget>,
    /// <p>The tags of the DataIntegrationFlow to be created</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateDataIntegrationFlowInput {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>Name of the DataIntegrationFlow.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The source configurations for DataIntegrationFlow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sources.is_none()`.
    pub fn sources(&self) -> &[crate::types::DataIntegrationFlowSource] {
        self.sources.as_deref().unwrap_or_default()
    }
    /// <p>The transformation configurations for DataIntegrationFlow.</p>
    pub fn transformation(&self) -> ::std::option::Option<&crate::types::DataIntegrationFlowTransformation> {
        self.transformation.as_ref()
    }
    /// <p>The target configurations for DataIntegrationFlow.</p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::DataIntegrationFlowTarget> {
        self.target.as_ref()
    }
    /// <p>The tags of the DataIntegrationFlow to be created</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateDataIntegrationFlowInput {
    /// Creates a new builder-style object to manufacture [`CreateDataIntegrationFlowInput`](crate::operation::create_data_integration_flow::CreateDataIntegrationFlowInput).
    pub fn builder() -> crate::operation::create_data_integration_flow::builders::CreateDataIntegrationFlowInputBuilder {
        crate::operation::create_data_integration_flow::builders::CreateDataIntegrationFlowInputBuilder::default()
    }
}

/// A builder for [`CreateDataIntegrationFlowInput`](crate::operation::create_data_integration_flow::CreateDataIntegrationFlowInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDataIntegrationFlowInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) sources: ::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationFlowSource>>,
    pub(crate) transformation: ::std::option::Option<crate::types::DataIntegrationFlowTransformation>,
    pub(crate) target: ::std::option::Option<crate::types::DataIntegrationFlowTarget>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateDataIntegrationFlowInputBuilder {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>Name of the DataIntegrationFlow.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the DataIntegrationFlow.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the DataIntegrationFlow.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `sources`.
    ///
    /// To override the contents of this collection use [`set_sources`](Self::set_sources).
    ///
    /// <p>The source configurations for DataIntegrationFlow.</p>
    pub fn sources(mut self, input: crate::types::DataIntegrationFlowSource) -> Self {
        let mut v = self.sources.unwrap_or_default();
        v.push(input);
        self.sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The source configurations for DataIntegrationFlow.</p>
    pub fn set_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationFlowSource>>) -> Self {
        self.sources = input;
        self
    }
    /// <p>The source configurations for DataIntegrationFlow.</p>
    pub fn get_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataIntegrationFlowSource>> {
        &self.sources
    }
    /// <p>The transformation configurations for DataIntegrationFlow.</p>
    /// This field is required.
    pub fn transformation(mut self, input: crate::types::DataIntegrationFlowTransformation) -> Self {
        self.transformation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The transformation configurations for DataIntegrationFlow.</p>
    pub fn set_transformation(mut self, input: ::std::option::Option<crate::types::DataIntegrationFlowTransformation>) -> Self {
        self.transformation = input;
        self
    }
    /// <p>The transformation configurations for DataIntegrationFlow.</p>
    pub fn get_transformation(&self) -> &::std::option::Option<crate::types::DataIntegrationFlowTransformation> {
        &self.transformation
    }
    /// <p>The target configurations for DataIntegrationFlow.</p>
    /// This field is required.
    pub fn target(mut self, input: crate::types::DataIntegrationFlowTarget) -> Self {
        self.target = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target configurations for DataIntegrationFlow.</p>
    pub fn set_target(mut self, input: ::std::option::Option<crate::types::DataIntegrationFlowTarget>) -> Self {
        self.target = input;
        self
    }
    /// <p>The target configurations for DataIntegrationFlow.</p>
    pub fn get_target(&self) -> &::std::option::Option<crate::types::DataIntegrationFlowTarget> {
        &self.target
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags of the DataIntegrationFlow to be created</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags of the DataIntegrationFlow to be created</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags of the DataIntegrationFlow to be created</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateDataIntegrationFlowInput`](crate::operation::create_data_integration_flow::CreateDataIntegrationFlowInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_data_integration_flow::CreateDataIntegrationFlowInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_data_integration_flow::CreateDataIntegrationFlowInput {
            instance_id: self.instance_id,
            name: self.name,
            sources: self.sources,
            transformation: self.transformation,
            target: self.target,
            tags: self.tags,
        })
    }
}
