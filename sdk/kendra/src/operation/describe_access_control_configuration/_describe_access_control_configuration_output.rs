// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAccessControlConfigurationOutput {
    /// <p>The name for the access control configuration.</p>
    pub name: ::std::string::String,
    /// <p>The description for the access control configuration.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The error message containing details if there are issues processing the access control configuration.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>Information on principals (users and/or groups) and which documents they should have access to. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p>
    pub access_control_list: ::std::option::Option<::std::vec::Vec<crate::types::Principal>>,
    /// <p>The list of <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Principal.html">principal</a> lists that define the hierarchy for which documents users should have access to.</p>
    pub hierarchical_access_control_list: ::std::option::Option<::std::vec::Vec<crate::types::HierarchicalPrincipal>>,
    _request_id: Option<String>,
}
impl DescribeAccessControlConfigurationOutput {
    /// <p>The name for the access control configuration.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description for the access control configuration.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The error message containing details if there are issues processing the access control configuration.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>Information on principals (users and/or groups) and which documents they should have access to. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.access_control_list.is_none()`.
    pub fn access_control_list(&self) -> &[crate::types::Principal] {
        self.access_control_list.as_deref().unwrap_or_default()
    }
    /// <p>The list of <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Principal.html">principal</a> lists that define the hierarchy for which documents users should have access to.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.hierarchical_access_control_list.is_none()`.
    pub fn hierarchical_access_control_list(&self) -> &[crate::types::HierarchicalPrincipal] {
        self.hierarchical_access_control_list.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeAccessControlConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeAccessControlConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeAccessControlConfigurationOutput`](crate::operation::describe_access_control_configuration::DescribeAccessControlConfigurationOutput).
    pub fn builder() -> crate::operation::describe_access_control_configuration::builders::DescribeAccessControlConfigurationOutputBuilder {
        crate::operation::describe_access_control_configuration::builders::DescribeAccessControlConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DescribeAccessControlConfigurationOutput`](crate::operation::describe_access_control_configuration::DescribeAccessControlConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAccessControlConfigurationOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) access_control_list: ::std::option::Option<::std::vec::Vec<crate::types::Principal>>,
    pub(crate) hierarchical_access_control_list: ::std::option::Option<::std::vec::Vec<crate::types::HierarchicalPrincipal>>,
    _request_id: Option<String>,
}
impl DescribeAccessControlConfigurationOutputBuilder {
    /// <p>The name for the access control configuration.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the access control configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name for the access control configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description for the access control configuration.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for the access control configuration.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description for the access control configuration.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The error message containing details if there are issues processing the access control configuration.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message containing details if there are issues processing the access control configuration.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The error message containing details if there are issues processing the access control configuration.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Appends an item to `access_control_list`.
    ///
    /// To override the contents of this collection use [`set_access_control_list`](Self::set_access_control_list).
    ///
    /// <p>Information on principals (users and/or groups) and which documents they should have access to. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p>
    pub fn access_control_list(mut self, input: crate::types::Principal) -> Self {
        let mut v = self.access_control_list.unwrap_or_default();
        v.push(input);
        self.access_control_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information on principals (users and/or groups) and which documents they should have access to. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p>
    pub fn set_access_control_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Principal>>) -> Self {
        self.access_control_list = input;
        self
    }
    /// <p>Information on principals (users and/or groups) and which documents they should have access to. This is useful for user context filtering, where search results are filtered based on the user or their group access to documents.</p>
    pub fn get_access_control_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Principal>> {
        &self.access_control_list
    }
    /// Appends an item to `hierarchical_access_control_list`.
    ///
    /// To override the contents of this collection use [`set_hierarchical_access_control_list`](Self::set_hierarchical_access_control_list).
    ///
    /// <p>The list of <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Principal.html">principal</a> lists that define the hierarchy for which documents users should have access to.</p>
    pub fn hierarchical_access_control_list(mut self, input: crate::types::HierarchicalPrincipal) -> Self {
        let mut v = self.hierarchical_access_control_list.unwrap_or_default();
        v.push(input);
        self.hierarchical_access_control_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Principal.html">principal</a> lists that define the hierarchy for which documents users should have access to.</p>
    pub fn set_hierarchical_access_control_list(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::HierarchicalPrincipal>>,
    ) -> Self {
        self.hierarchical_access_control_list = input;
        self
    }
    /// <p>The list of <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Principal.html">principal</a> lists that define the hierarchy for which documents users should have access to.</p>
    pub fn get_hierarchical_access_control_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::HierarchicalPrincipal>> {
        &self.hierarchical_access_control_list
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeAccessControlConfigurationOutput`](crate::operation::describe_access_control_configuration::DescribeAccessControlConfigurationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::operation::describe_access_control_configuration::builders::DescribeAccessControlConfigurationOutputBuilder::name)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_access_control_configuration::DescribeAccessControlConfigurationOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_access_control_configuration::DescribeAccessControlConfigurationOutput {
                name: self.name.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "name",
                        "name was not specified but it is required when building DescribeAccessControlConfigurationOutput",
                    )
                })?,
                description: self.description,
                error_message: self.error_message,
                access_control_list: self.access_control_list,
                hierarchical_access_control_list: self.hierarchical_access_control_list,
                _request_id: self._request_id,
            },
        )
    }
}
