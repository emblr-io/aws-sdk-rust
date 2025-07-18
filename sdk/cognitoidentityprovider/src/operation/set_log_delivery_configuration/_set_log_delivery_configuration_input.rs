// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SetLogDeliveryConfigurationInput {
    /// <p>The ID of the user pool where you want to configure logging.</p>
    pub user_pool_id: ::std::option::Option<::std::string::String>,
    /// <p>A collection of the logging configurations for a user pool.</p>
    pub log_configurations: ::std::option::Option<::std::vec::Vec<crate::types::LogConfigurationType>>,
}
impl SetLogDeliveryConfigurationInput {
    /// <p>The ID of the user pool where you want to configure logging.</p>
    pub fn user_pool_id(&self) -> ::std::option::Option<&str> {
        self.user_pool_id.as_deref()
    }
    /// <p>A collection of the logging configurations for a user pool.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_configurations.is_none()`.
    pub fn log_configurations(&self) -> &[crate::types::LogConfigurationType] {
        self.log_configurations.as_deref().unwrap_or_default()
    }
}
impl SetLogDeliveryConfigurationInput {
    /// Creates a new builder-style object to manufacture [`SetLogDeliveryConfigurationInput`](crate::operation::set_log_delivery_configuration::SetLogDeliveryConfigurationInput).
    pub fn builder() -> crate::operation::set_log_delivery_configuration::builders::SetLogDeliveryConfigurationInputBuilder {
        crate::operation::set_log_delivery_configuration::builders::SetLogDeliveryConfigurationInputBuilder::default()
    }
}

/// A builder for [`SetLogDeliveryConfigurationInput`](crate::operation::set_log_delivery_configuration::SetLogDeliveryConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SetLogDeliveryConfigurationInputBuilder {
    pub(crate) user_pool_id: ::std::option::Option<::std::string::String>,
    pub(crate) log_configurations: ::std::option::Option<::std::vec::Vec<crate::types::LogConfigurationType>>,
}
impl SetLogDeliveryConfigurationInputBuilder {
    /// <p>The ID of the user pool where you want to configure logging.</p>
    /// This field is required.
    pub fn user_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the user pool where you want to configure logging.</p>
    pub fn set_user_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_id = input;
        self
    }
    /// <p>The ID of the user pool where you want to configure logging.</p>
    pub fn get_user_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_id
    }
    /// Appends an item to `log_configurations`.
    ///
    /// To override the contents of this collection use [`set_log_configurations`](Self::set_log_configurations).
    ///
    /// <p>A collection of the logging configurations for a user pool.</p>
    pub fn log_configurations(mut self, input: crate::types::LogConfigurationType) -> Self {
        let mut v = self.log_configurations.unwrap_or_default();
        v.push(input);
        self.log_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of the logging configurations for a user pool.</p>
    pub fn set_log_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LogConfigurationType>>) -> Self {
        self.log_configurations = input;
        self
    }
    /// <p>A collection of the logging configurations for a user pool.</p>
    pub fn get_log_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LogConfigurationType>> {
        &self.log_configurations
    }
    /// Consumes the builder and constructs a [`SetLogDeliveryConfigurationInput`](crate::operation::set_log_delivery_configuration::SetLogDeliveryConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::set_log_delivery_configuration::SetLogDeliveryConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::set_log_delivery_configuration::SetLogDeliveryConfigurationInput {
            user_pool_id: self.user_pool_id,
            log_configurations: self.log_configurations,
        })
    }
}
