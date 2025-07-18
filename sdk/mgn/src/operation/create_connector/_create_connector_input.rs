// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateConnectorInput {
    /// <p>Create Connector request name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Create Connector request SSM instance ID.</p>
    pub ssm_instance_id: ::std::option::Option<::std::string::String>,
    /// <p>Create Connector request tags.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Create Connector request SSM command config.</p>
    pub ssm_command_config: ::std::option::Option<crate::types::ConnectorSsmCommandConfig>,
}
impl CreateConnectorInput {
    /// <p>Create Connector request name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Create Connector request SSM instance ID.</p>
    pub fn ssm_instance_id(&self) -> ::std::option::Option<&str> {
        self.ssm_instance_id.as_deref()
    }
    /// <p>Create Connector request tags.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Create Connector request SSM command config.</p>
    pub fn ssm_command_config(&self) -> ::std::option::Option<&crate::types::ConnectorSsmCommandConfig> {
        self.ssm_command_config.as_ref()
    }
}
impl ::std::fmt::Debug for CreateConnectorInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateConnectorInput");
        formatter.field("name", &self.name);
        formatter.field("ssm_instance_id", &self.ssm_instance_id);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.field("ssm_command_config", &self.ssm_command_config);
        formatter.finish()
    }
}
impl CreateConnectorInput {
    /// Creates a new builder-style object to manufacture [`CreateConnectorInput`](crate::operation::create_connector::CreateConnectorInput).
    pub fn builder() -> crate::operation::create_connector::builders::CreateConnectorInputBuilder {
        crate::operation::create_connector::builders::CreateConnectorInputBuilder::default()
    }
}

/// A builder for [`CreateConnectorInput`](crate::operation::create_connector::CreateConnectorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateConnectorInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) ssm_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) ssm_command_config: ::std::option::Option<crate::types::ConnectorSsmCommandConfig>,
}
impl CreateConnectorInputBuilder {
    /// <p>Create Connector request name.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Create Connector request name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Create Connector request name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Create Connector request SSM instance ID.</p>
    /// This field is required.
    pub fn ssm_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ssm_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Create Connector request SSM instance ID.</p>
    pub fn set_ssm_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ssm_instance_id = input;
        self
    }
    /// <p>Create Connector request SSM instance ID.</p>
    pub fn get_ssm_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ssm_instance_id
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Create Connector request tags.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Create Connector request tags.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Create Connector request tags.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>Create Connector request SSM command config.</p>
    pub fn ssm_command_config(mut self, input: crate::types::ConnectorSsmCommandConfig) -> Self {
        self.ssm_command_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Create Connector request SSM command config.</p>
    pub fn set_ssm_command_config(mut self, input: ::std::option::Option<crate::types::ConnectorSsmCommandConfig>) -> Self {
        self.ssm_command_config = input;
        self
    }
    /// <p>Create Connector request SSM command config.</p>
    pub fn get_ssm_command_config(&self) -> &::std::option::Option<crate::types::ConnectorSsmCommandConfig> {
        &self.ssm_command_config
    }
    /// Consumes the builder and constructs a [`CreateConnectorInput`](crate::operation::create_connector::CreateConnectorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_connector::CreateConnectorInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_connector::CreateConnectorInput {
            name: self.name,
            ssm_instance_id: self.ssm_instance_id,
            tags: self.tags,
            ssm_command_config: self.ssm_command_config,
        })
    }
}
impl ::std::fmt::Debug for CreateConnectorInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateConnectorInputBuilder");
        formatter.field("name", &self.name);
        formatter.field("ssm_instance_id", &self.ssm_instance_id);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.field("ssm_command_config", &self.ssm_command_config);
        formatter.finish()
    }
}
