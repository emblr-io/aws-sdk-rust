// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFolderResolvedPermissionsInput {
    /// <p>The ID for the Amazon Web Services account that contains the folder.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the folder.</p>
    pub folder_id: ::std::option::Option<::std::string::String>,
    /// <p>The namespace of the folder whose permissions you want described.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to be returned per request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A pagination token for the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeFolderResolvedPermissionsInput {
    /// <p>The ID for the Amazon Web Services account that contains the folder.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID of the folder.</p>
    pub fn folder_id(&self) -> ::std::option::Option<&str> {
        self.folder_id.as_deref()
    }
    /// <p>The namespace of the folder whose permissions you want described.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A pagination token for the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeFolderResolvedPermissionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeFolderResolvedPermissionsInput`](crate::operation::describe_folder_resolved_permissions::DescribeFolderResolvedPermissionsInput).
    pub fn builder() -> crate::operation::describe_folder_resolved_permissions::builders::DescribeFolderResolvedPermissionsInputBuilder {
        crate::operation::describe_folder_resolved_permissions::builders::DescribeFolderResolvedPermissionsInputBuilder::default()
    }
}

/// A builder for [`DescribeFolderResolvedPermissionsInput`](crate::operation::describe_folder_resolved_permissions::DescribeFolderResolvedPermissionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFolderResolvedPermissionsInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) folder_id: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeFolderResolvedPermissionsInputBuilder {
    /// <p>The ID for the Amazon Web Services account that contains the folder.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the Amazon Web Services account that contains the folder.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID for the Amazon Web Services account that contains the folder.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID of the folder.</p>
    /// This field is required.
    pub fn folder_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.folder_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the folder.</p>
    pub fn set_folder_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.folder_id = input;
        self
    }
    /// <p>The ID of the folder.</p>
    pub fn get_folder_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.folder_id
    }
    /// <p>The namespace of the folder whose permissions you want described.</p>
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the folder whose permissions you want described.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace of the folder whose permissions you want described.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A pagination token for the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token for the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token for the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeFolderResolvedPermissionsInput`](crate::operation::describe_folder_resolved_permissions::DescribeFolderResolvedPermissionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_folder_resolved_permissions::DescribeFolderResolvedPermissionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_folder_resolved_permissions::DescribeFolderResolvedPermissionsInput {
                aws_account_id: self.aws_account_id,
                folder_id: self.folder_id,
                namespace: self.namespace,
                max_results: self.max_results,
                next_token: self.next_token,
            },
        )
    }
}
