// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAccountPreferencesInput {
    /// <p>Specifies the EFS resource ID preference to set for the user's Amazon Web Services account, in the current Amazon Web Services Region, either <code>LONG_ID</code> (17 characters), or <code>SHORT_ID</code> (8 characters).</p><note>
    /// <p>Starting in October, 2021, you will receive an error when setting the account preference to <code>SHORT_ID</code>. Contact Amazon Web Services support if you receive an error and must use short IDs for file system and mount target resources.</p>
    /// </note>
    pub resource_id_type: ::std::option::Option<crate::types::ResourceIdType>,
}
impl PutAccountPreferencesInput {
    /// <p>Specifies the EFS resource ID preference to set for the user's Amazon Web Services account, in the current Amazon Web Services Region, either <code>LONG_ID</code> (17 characters), or <code>SHORT_ID</code> (8 characters).</p><note>
    /// <p>Starting in October, 2021, you will receive an error when setting the account preference to <code>SHORT_ID</code>. Contact Amazon Web Services support if you receive an error and must use short IDs for file system and mount target resources.</p>
    /// </note>
    pub fn resource_id_type(&self) -> ::std::option::Option<&crate::types::ResourceIdType> {
        self.resource_id_type.as_ref()
    }
}
impl PutAccountPreferencesInput {
    /// Creates a new builder-style object to manufacture [`PutAccountPreferencesInput`](crate::operation::put_account_preferences::PutAccountPreferencesInput).
    pub fn builder() -> crate::operation::put_account_preferences::builders::PutAccountPreferencesInputBuilder {
        crate::operation::put_account_preferences::builders::PutAccountPreferencesInputBuilder::default()
    }
}

/// A builder for [`PutAccountPreferencesInput`](crate::operation::put_account_preferences::PutAccountPreferencesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAccountPreferencesInputBuilder {
    pub(crate) resource_id_type: ::std::option::Option<crate::types::ResourceIdType>,
}
impl PutAccountPreferencesInputBuilder {
    /// <p>Specifies the EFS resource ID preference to set for the user's Amazon Web Services account, in the current Amazon Web Services Region, either <code>LONG_ID</code> (17 characters), or <code>SHORT_ID</code> (8 characters).</p><note>
    /// <p>Starting in October, 2021, you will receive an error when setting the account preference to <code>SHORT_ID</code>. Contact Amazon Web Services support if you receive an error and must use short IDs for file system and mount target resources.</p>
    /// </note>
    /// This field is required.
    pub fn resource_id_type(mut self, input: crate::types::ResourceIdType) -> Self {
        self.resource_id_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the EFS resource ID preference to set for the user's Amazon Web Services account, in the current Amazon Web Services Region, either <code>LONG_ID</code> (17 characters), or <code>SHORT_ID</code> (8 characters).</p><note>
    /// <p>Starting in October, 2021, you will receive an error when setting the account preference to <code>SHORT_ID</code>. Contact Amazon Web Services support if you receive an error and must use short IDs for file system and mount target resources.</p>
    /// </note>
    pub fn set_resource_id_type(mut self, input: ::std::option::Option<crate::types::ResourceIdType>) -> Self {
        self.resource_id_type = input;
        self
    }
    /// <p>Specifies the EFS resource ID preference to set for the user's Amazon Web Services account, in the current Amazon Web Services Region, either <code>LONG_ID</code> (17 characters), or <code>SHORT_ID</code> (8 characters).</p><note>
    /// <p>Starting in October, 2021, you will receive an error when setting the account preference to <code>SHORT_ID</code>. Contact Amazon Web Services support if you receive an error and must use short IDs for file system and mount target resources.</p>
    /// </note>
    pub fn get_resource_id_type(&self) -> &::std::option::Option<crate::types::ResourceIdType> {
        &self.resource_id_type
    }
    /// Consumes the builder and constructs a [`PutAccountPreferencesInput`](crate::operation::put_account_preferences::PutAccountPreferencesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_account_preferences::PutAccountPreferencesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::put_account_preferences::PutAccountPreferencesInput {
            resource_id_type: self.resource_id_type,
        })
    }
}
