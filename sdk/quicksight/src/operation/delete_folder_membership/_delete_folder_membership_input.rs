// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteFolderMembershipInput {
    /// <p>The ID for the Amazon Web Services account that contains the folder.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The Folder ID.</p>
    pub folder_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the asset that you want to delete.</p>
    pub member_id: ::std::option::Option<::std::string::String>,
    /// <p>The member type of the asset that you want to delete from a folder.</p>
    pub member_type: ::std::option::Option<crate::types::MemberType>,
}
impl DeleteFolderMembershipInput {
    /// <p>The ID for the Amazon Web Services account that contains the folder.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The Folder ID.</p>
    pub fn folder_id(&self) -> ::std::option::Option<&str> {
        self.folder_id.as_deref()
    }
    /// <p>The ID of the asset that you want to delete.</p>
    pub fn member_id(&self) -> ::std::option::Option<&str> {
        self.member_id.as_deref()
    }
    /// <p>The member type of the asset that you want to delete from a folder.</p>
    pub fn member_type(&self) -> ::std::option::Option<&crate::types::MemberType> {
        self.member_type.as_ref()
    }
}
impl DeleteFolderMembershipInput {
    /// Creates a new builder-style object to manufacture [`DeleteFolderMembershipInput`](crate::operation::delete_folder_membership::DeleteFolderMembershipInput).
    pub fn builder() -> crate::operation::delete_folder_membership::builders::DeleteFolderMembershipInputBuilder {
        crate::operation::delete_folder_membership::builders::DeleteFolderMembershipInputBuilder::default()
    }
}

/// A builder for [`DeleteFolderMembershipInput`](crate::operation::delete_folder_membership::DeleteFolderMembershipInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteFolderMembershipInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) folder_id: ::std::option::Option<::std::string::String>,
    pub(crate) member_id: ::std::option::Option<::std::string::String>,
    pub(crate) member_type: ::std::option::Option<crate::types::MemberType>,
}
impl DeleteFolderMembershipInputBuilder {
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
    /// <p>The Folder ID.</p>
    /// This field is required.
    pub fn folder_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.folder_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Folder ID.</p>
    pub fn set_folder_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.folder_id = input;
        self
    }
    /// <p>The Folder ID.</p>
    pub fn get_folder_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.folder_id
    }
    /// <p>The ID of the asset that you want to delete.</p>
    /// This field is required.
    pub fn member_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.member_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset that you want to delete.</p>
    pub fn set_member_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.member_id = input;
        self
    }
    /// <p>The ID of the asset that you want to delete.</p>
    pub fn get_member_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.member_id
    }
    /// <p>The member type of the asset that you want to delete from a folder.</p>
    /// This field is required.
    pub fn member_type(mut self, input: crate::types::MemberType) -> Self {
        self.member_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The member type of the asset that you want to delete from a folder.</p>
    pub fn set_member_type(mut self, input: ::std::option::Option<crate::types::MemberType>) -> Self {
        self.member_type = input;
        self
    }
    /// <p>The member type of the asset that you want to delete from a folder.</p>
    pub fn get_member_type(&self) -> &::std::option::Option<crate::types::MemberType> {
        &self.member_type
    }
    /// Consumes the builder and constructs a [`DeleteFolderMembershipInput`](crate::operation::delete_folder_membership::DeleteFolderMembershipInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_folder_membership::DeleteFolderMembershipInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_folder_membership::DeleteFolderMembershipInput {
            aws_account_id: self.aws_account_id,
            folder_id: self.folder_id,
            member_id: self.member_id,
            member_type: self.member_type,
        })
    }
}
