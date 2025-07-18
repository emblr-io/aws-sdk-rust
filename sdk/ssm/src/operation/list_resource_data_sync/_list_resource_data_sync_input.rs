// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListResourceDataSyncInput {
    /// <p>View a list of resource data syncs according to the sync type. Specify <code>SyncToDestination</code> to view resource data syncs that synchronize data to an Amazon S3 bucket. Specify <code>SyncFromSource</code> to view resource data syncs from Organizations or from multiple Amazon Web Services Regions.</p>
    pub sync_type: ::std::option::Option<::std::string::String>,
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListResourceDataSyncInput {
    /// <p>View a list of resource data syncs according to the sync type. Specify <code>SyncToDestination</code> to view resource data syncs that synchronize data to an Amazon S3 bucket. Specify <code>SyncFromSource</code> to view resource data syncs from Organizations or from multiple Amazon Web Services Regions.</p>
    pub fn sync_type(&self) -> ::std::option::Option<&str> {
        self.sync_type.as_deref()
    }
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListResourceDataSyncInput {
    /// Creates a new builder-style object to manufacture [`ListResourceDataSyncInput`](crate::operation::list_resource_data_sync::ListResourceDataSyncInput).
    pub fn builder() -> crate::operation::list_resource_data_sync::builders::ListResourceDataSyncInputBuilder {
        crate::operation::list_resource_data_sync::builders::ListResourceDataSyncInputBuilder::default()
    }
}

/// A builder for [`ListResourceDataSyncInput`](crate::operation::list_resource_data_sync::ListResourceDataSyncInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListResourceDataSyncInputBuilder {
    pub(crate) sync_type: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListResourceDataSyncInputBuilder {
    /// <p>View a list of resource data syncs according to the sync type. Specify <code>SyncToDestination</code> to view resource data syncs that synchronize data to an Amazon S3 bucket. Specify <code>SyncFromSource</code> to view resource data syncs from Organizations or from multiple Amazon Web Services Regions.</p>
    pub fn sync_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sync_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>View a list of resource data syncs according to the sync type. Specify <code>SyncToDestination</code> to view resource data syncs that synchronize data to an Amazon S3 bucket. Specify <code>SyncFromSource</code> to view resource data syncs from Organizations or from multiple Amazon Web Services Regions.</p>
    pub fn set_sync_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sync_type = input;
        self
    }
    /// <p>View a list of resource data syncs according to the sync type. Specify <code>SyncToDestination</code> to view resource data syncs that synchronize data to an Amazon S3 bucket. Specify <code>SyncFromSource</code> to view resource data syncs from Organizations or from multiple Amazon Web Services Regions.</p>
    pub fn get_sync_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.sync_type
    }
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to start the list. Use this token to get the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that you can specify in a subsequent call to get the next set of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListResourceDataSyncInput`](crate::operation::list_resource_data_sync::ListResourceDataSyncInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_resource_data_sync::ListResourceDataSyncInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_resource_data_sync::ListResourceDataSyncInput {
            sync_type: self.sync_type,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
