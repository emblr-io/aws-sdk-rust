// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRetentionConfigurationsInput {
    /// <p>A list of names of retention configurations for which you want details. If you do not specify a name, Config returns details for all the retention configurations for that account.</p><note>
    /// <p>Currently, Config supports only one retention configuration per region in your account.</p>
    /// </note>
    pub retention_configuration_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeRetentionConfigurationsInput {
    /// <p>A list of names of retention configurations for which you want details. If you do not specify a name, Config returns details for all the retention configurations for that account.</p><note>
    /// <p>Currently, Config supports only one retention configuration per region in your account.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.retention_configuration_names.is_none()`.
    pub fn retention_configuration_names(&self) -> &[::std::string::String] {
        self.retention_configuration_names.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeRetentionConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`DescribeRetentionConfigurationsInput`](crate::operation::describe_retention_configurations::DescribeRetentionConfigurationsInput).
    pub fn builder() -> crate::operation::describe_retention_configurations::builders::DescribeRetentionConfigurationsInputBuilder {
        crate::operation::describe_retention_configurations::builders::DescribeRetentionConfigurationsInputBuilder::default()
    }
}

/// A builder for [`DescribeRetentionConfigurationsInput`](crate::operation::describe_retention_configurations::DescribeRetentionConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRetentionConfigurationsInputBuilder {
    pub(crate) retention_configuration_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeRetentionConfigurationsInputBuilder {
    /// Appends an item to `retention_configuration_names`.
    ///
    /// To override the contents of this collection use [`set_retention_configuration_names`](Self::set_retention_configuration_names).
    ///
    /// <p>A list of names of retention configurations for which you want details. If you do not specify a name, Config returns details for all the retention configurations for that account.</p><note>
    /// <p>Currently, Config supports only one retention configuration per region in your account.</p>
    /// </note>
    pub fn retention_configuration_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.retention_configuration_names.unwrap_or_default();
        v.push(input.into());
        self.retention_configuration_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of names of retention configurations for which you want details. If you do not specify a name, Config returns details for all the retention configurations for that account.</p><note>
    /// <p>Currently, Config supports only one retention configuration per region in your account.</p>
    /// </note>
    pub fn set_retention_configuration_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.retention_configuration_names = input;
        self
    }
    /// <p>A list of names of retention configurations for which you want details. If you do not specify a name, Config returns details for all the retention configurations for that account.</p><note>
    /// <p>Currently, Config supports only one retention configuration per region in your account.</p>
    /// </note>
    pub fn get_retention_configuration_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.retention_configuration_names
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeRetentionConfigurationsInput`](crate::operation::describe_retention_configurations::DescribeRetentionConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_retention_configurations::DescribeRetentionConfigurationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_retention_configurations::DescribeRetentionConfigurationsInput {
                retention_configuration_names: self.retention_configuration_names,
                next_token: self.next_token,
            },
        )
    }
}
