// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListConfigurationsInput {
    /// <p>The token to use when requesting a specific set of items from a list.</p>
    pub starting_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the maximum number of configurations that are returned by the request.</p>
    pub max_items: ::std::option::Option<i32>,
    /// <p>Filters the results returned by the request.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The ARN of the configuration manager.</p>
    pub manager_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the configuration definition.</p>
    pub configuration_definition_id: ::std::option::Option<::std::string::String>,
}
impl ListConfigurationsInput {
    /// <p>The token to use when requesting a specific set of items from a list.</p>
    pub fn starting_token(&self) -> ::std::option::Option<&str> {
        self.starting_token.as_deref()
    }
    /// <p>Specifies the maximum number of configurations that are returned by the request.</p>
    pub fn max_items(&self) -> ::std::option::Option<i32> {
        self.max_items
    }
    /// <p>Filters the results returned by the request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The ARN of the configuration manager.</p>
    pub fn manager_arn(&self) -> ::std::option::Option<&str> {
        self.manager_arn.as_deref()
    }
    /// <p>The ID of the configuration definition.</p>
    pub fn configuration_definition_id(&self) -> ::std::option::Option<&str> {
        self.configuration_definition_id.as_deref()
    }
}
impl ListConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`ListConfigurationsInput`](crate::operation::list_configurations::ListConfigurationsInput).
    pub fn builder() -> crate::operation::list_configurations::builders::ListConfigurationsInputBuilder {
        crate::operation::list_configurations::builders::ListConfigurationsInputBuilder::default()
    }
}

/// A builder for [`ListConfigurationsInput`](crate::operation::list_configurations::ListConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListConfigurationsInputBuilder {
    pub(crate) starting_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) manager_arn: ::std::option::Option<::std::string::String>,
    pub(crate) configuration_definition_id: ::std::option::Option<::std::string::String>,
}
impl ListConfigurationsInputBuilder {
    /// <p>The token to use when requesting a specific set of items from a list.</p>
    pub fn starting_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.starting_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use when requesting a specific set of items from a list.</p>
    pub fn set_starting_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.starting_token = input;
        self
    }
    /// <p>The token to use when requesting a specific set of items from a list.</p>
    pub fn get_starting_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.starting_token
    }
    /// <p>Specifies the maximum number of configurations that are returned by the request.</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the maximum number of configurations that are returned by the request.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>Specifies the maximum number of configurations that are returned by the request.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>Filters the results returned by the request.</p>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the results returned by the request.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Filters the results returned by the request.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The ARN of the configuration manager.</p>
    pub fn manager_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.manager_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the configuration manager.</p>
    pub fn set_manager_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.manager_arn = input;
        self
    }
    /// <p>The ARN of the configuration manager.</p>
    pub fn get_manager_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.manager_arn
    }
    /// <p>The ID of the configuration definition.</p>
    pub fn configuration_definition_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_definition_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the configuration definition.</p>
    pub fn set_configuration_definition_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_definition_id = input;
        self
    }
    /// <p>The ID of the configuration definition.</p>
    pub fn get_configuration_definition_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_definition_id
    }
    /// Consumes the builder and constructs a [`ListConfigurationsInput`](crate::operation::list_configurations::ListConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_configurations::ListConfigurationsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_configurations::ListConfigurationsInput {
            starting_token: self.starting_token,
            max_items: self.max_items,
            filters: self.filters,
            manager_arn: self.manager_arn,
            configuration_definition_id: self.configuration_definition_id,
        })
    }
}
