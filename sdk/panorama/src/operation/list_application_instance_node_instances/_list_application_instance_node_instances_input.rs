// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListApplicationInstanceNodeInstancesInput {
    /// <p>The node instances' application instance ID.</p>
    pub application_instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of node instances to return in one page of results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListApplicationInstanceNodeInstancesInput {
    /// <p>The node instances' application instance ID.</p>
    pub fn application_instance_id(&self) -> ::std::option::Option<&str> {
        self.application_instance_id.as_deref()
    }
    /// <p>The maximum number of node instances to return in one page of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListApplicationInstanceNodeInstancesInput {
    /// Creates a new builder-style object to manufacture [`ListApplicationInstanceNodeInstancesInput`](crate::operation::list_application_instance_node_instances::ListApplicationInstanceNodeInstancesInput).
    pub fn builder() -> crate::operation::list_application_instance_node_instances::builders::ListApplicationInstanceNodeInstancesInputBuilder {
        crate::operation::list_application_instance_node_instances::builders::ListApplicationInstanceNodeInstancesInputBuilder::default()
    }
}

/// A builder for [`ListApplicationInstanceNodeInstancesInput`](crate::operation::list_application_instance_node_instances::ListApplicationInstanceNodeInstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListApplicationInstanceNodeInstancesInputBuilder {
    pub(crate) application_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListApplicationInstanceNodeInstancesInputBuilder {
    /// <p>The node instances' application instance ID.</p>
    /// This field is required.
    pub fn application_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The node instances' application instance ID.</p>
    pub fn set_application_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_instance_id = input;
        self
    }
    /// <p>The node instances' application instance ID.</p>
    pub fn get_application_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_instance_id
    }
    /// <p>The maximum number of node instances to return in one page of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of node instances to return in one page of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of node instances to return in one page of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Specify the pagination token from a previous request to retrieve the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListApplicationInstanceNodeInstancesInput`](crate::operation::list_application_instance_node_instances::ListApplicationInstanceNodeInstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_application_instance_node_instances::ListApplicationInstanceNodeInstancesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_application_instance_node_instances::ListApplicationInstanceNodeInstancesInput {
                application_instance_id: self.application_instance_id,
                max_results: self.max_results,
                next_token: self.next_token,
            },
        )
    }
}
