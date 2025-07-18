// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// A request to post updates to records or add and delete records for a dataset and user.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRecordsInput {
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    pub identity_pool_id: ::std::option::Option<::std::string::String>,
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    pub identity_id: ::std::option::Option<::std::string::String>,
    /// A string of up to 128 characters. Allowed characters are a-z, A-Z, 0-9, '_' (underscore), '-' (dash), and '.' (dot).
    pub dataset_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique ID generated for this device by Cognito.</p>
    pub device_id: ::std::option::Option<::std::string::String>,
    /// A list of patch operations.
    pub record_patches: ::std::option::Option<::std::vec::Vec<crate::types::RecordPatch>>,
    /// The SyncSessionToken returned by a previous call to ListRecords for this dataset and identity.
    pub sync_session_token: ::std::option::Option<::std::string::String>,
    /// Intended to supply a device ID that will populate the lastModifiedBy field referenced in other methods. The ClientContext field is not yet implemented.
    pub client_context: ::std::option::Option<::std::string::String>,
}
impl UpdateRecordsInput {
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    pub fn identity_pool_id(&self) -> ::std::option::Option<&str> {
        self.identity_pool_id.as_deref()
    }
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    pub fn identity_id(&self) -> ::std::option::Option<&str> {
        self.identity_id.as_deref()
    }
    /// A string of up to 128 characters. Allowed characters are a-z, A-Z, 0-9, '_' (underscore), '-' (dash), and '.' (dot).
    pub fn dataset_name(&self) -> ::std::option::Option<&str> {
        self.dataset_name.as_deref()
    }
    /// <p>The unique ID generated for this device by Cognito.</p>
    pub fn device_id(&self) -> ::std::option::Option<&str> {
        self.device_id.as_deref()
    }
    /// A list of patch operations.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.record_patches.is_none()`.
    pub fn record_patches(&self) -> &[crate::types::RecordPatch] {
        self.record_patches.as_deref().unwrap_or_default()
    }
    /// The SyncSessionToken returned by a previous call to ListRecords for this dataset and identity.
    pub fn sync_session_token(&self) -> ::std::option::Option<&str> {
        self.sync_session_token.as_deref()
    }
    /// Intended to supply a device ID that will populate the lastModifiedBy field referenced in other methods. The ClientContext field is not yet implemented.
    pub fn client_context(&self) -> ::std::option::Option<&str> {
        self.client_context.as_deref()
    }
}
impl UpdateRecordsInput {
    /// Creates a new builder-style object to manufacture [`UpdateRecordsInput`](crate::operation::update_records::UpdateRecordsInput).
    pub fn builder() -> crate::operation::update_records::builders::UpdateRecordsInputBuilder {
        crate::operation::update_records::builders::UpdateRecordsInputBuilder::default()
    }
}

/// A builder for [`UpdateRecordsInput`](crate::operation::update_records::UpdateRecordsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRecordsInputBuilder {
    pub(crate) identity_pool_id: ::std::option::Option<::std::string::String>,
    pub(crate) identity_id: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_name: ::std::option::Option<::std::string::String>,
    pub(crate) device_id: ::std::option::Option<::std::string::String>,
    pub(crate) record_patches: ::std::option::Option<::std::vec::Vec<crate::types::RecordPatch>>,
    pub(crate) sync_session_token: ::std::option::Option<::std::string::String>,
    pub(crate) client_context: ::std::option::Option<::std::string::String>,
}
impl UpdateRecordsInputBuilder {
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    /// This field is required.
    pub fn identity_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    pub fn set_identity_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_pool_id = input;
        self
    }
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    pub fn get_identity_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_pool_id
    }
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    /// This field is required.
    pub fn identity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    pub fn set_identity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_id = input;
        self
    }
    /// A name-spaced GUID (for example, us-east-1:23EC4050-6AEA-7089-A2DD-08002EXAMPLE) created by Amazon Cognito. GUID generation is unique within a region.
    pub fn get_identity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_id
    }
    /// A string of up to 128 characters. Allowed characters are a-z, A-Z, 0-9, '_' (underscore), '-' (dash), and '.' (dot).
    /// This field is required.
    pub fn dataset_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_name = ::std::option::Option::Some(input.into());
        self
    }
    /// A string of up to 128 characters. Allowed characters are a-z, A-Z, 0-9, '_' (underscore), '-' (dash), and '.' (dot).
    pub fn set_dataset_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_name = input;
        self
    }
    /// A string of up to 128 characters. Allowed characters are a-z, A-Z, 0-9, '_' (underscore), '-' (dash), and '.' (dot).
    pub fn get_dataset_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_name
    }
    /// <p>The unique ID generated for this device by Cognito.</p>
    pub fn device_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID generated for this device by Cognito.</p>
    pub fn set_device_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_id = input;
        self
    }
    /// <p>The unique ID generated for this device by Cognito.</p>
    pub fn get_device_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_id
    }
    /// Appends an item to `record_patches`.
    ///
    /// To override the contents of this collection use [`set_record_patches`](Self::set_record_patches).
    ///
    /// A list of patch operations.
    pub fn record_patches(mut self, input: crate::types::RecordPatch) -> Self {
        let mut v = self.record_patches.unwrap_or_default();
        v.push(input);
        self.record_patches = ::std::option::Option::Some(v);
        self
    }
    /// A list of patch operations.
    pub fn set_record_patches(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RecordPatch>>) -> Self {
        self.record_patches = input;
        self
    }
    /// A list of patch operations.
    pub fn get_record_patches(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RecordPatch>> {
        &self.record_patches
    }
    /// The SyncSessionToken returned by a previous call to ListRecords for this dataset and identity.
    /// This field is required.
    pub fn sync_session_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sync_session_token = ::std::option::Option::Some(input.into());
        self
    }
    /// The SyncSessionToken returned by a previous call to ListRecords for this dataset and identity.
    pub fn set_sync_session_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sync_session_token = input;
        self
    }
    /// The SyncSessionToken returned by a previous call to ListRecords for this dataset and identity.
    pub fn get_sync_session_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.sync_session_token
    }
    /// Intended to supply a device ID that will populate the lastModifiedBy field referenced in other methods. The ClientContext field is not yet implemented.
    pub fn client_context(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_context = ::std::option::Option::Some(input.into());
        self
    }
    /// Intended to supply a device ID that will populate the lastModifiedBy field referenced in other methods. The ClientContext field is not yet implemented.
    pub fn set_client_context(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_context = input;
        self
    }
    /// Intended to supply a device ID that will populate the lastModifiedBy field referenced in other methods. The ClientContext field is not yet implemented.
    pub fn get_client_context(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_context
    }
    /// Consumes the builder and constructs a [`UpdateRecordsInput`](crate::operation::update_records::UpdateRecordsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_records::UpdateRecordsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_records::UpdateRecordsInput {
            identity_pool_id: self.identity_pool_id,
            identity_id: self.identity_id,
            dataset_name: self.dataset_name,
            device_id: self.device_id,
            record_patches: self.record_patches,
            sync_session_token: self.sync_session_token,
            client_context: self.client_context,
        })
    }
}
