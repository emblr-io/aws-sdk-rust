// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateEnrollmentStatusInput {
    /// <p>Sets the account status.</p>
    pub status: ::std::option::Option<crate::types::EnrollmentStatus>,
    /// <p>Indicates whether to enroll member accounts of the organization if the account is the management account or delegated administrator.</p>
    pub include_member_accounts: ::std::option::Option<bool>,
}
impl UpdateEnrollmentStatusInput {
    /// <p>Sets the account status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::EnrollmentStatus> {
        self.status.as_ref()
    }
    /// <p>Indicates whether to enroll member accounts of the organization if the account is the management account or delegated administrator.</p>
    pub fn include_member_accounts(&self) -> ::std::option::Option<bool> {
        self.include_member_accounts
    }
}
impl UpdateEnrollmentStatusInput {
    /// Creates a new builder-style object to manufacture [`UpdateEnrollmentStatusInput`](crate::operation::update_enrollment_status::UpdateEnrollmentStatusInput).
    pub fn builder() -> crate::operation::update_enrollment_status::builders::UpdateEnrollmentStatusInputBuilder {
        crate::operation::update_enrollment_status::builders::UpdateEnrollmentStatusInputBuilder::default()
    }
}

/// A builder for [`UpdateEnrollmentStatusInput`](crate::operation::update_enrollment_status::UpdateEnrollmentStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateEnrollmentStatusInputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::EnrollmentStatus>,
    pub(crate) include_member_accounts: ::std::option::Option<bool>,
}
impl UpdateEnrollmentStatusInputBuilder {
    /// <p>Sets the account status.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::EnrollmentStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets the account status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::EnrollmentStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Sets the account status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::EnrollmentStatus> {
        &self.status
    }
    /// <p>Indicates whether to enroll member accounts of the organization if the account is the management account or delegated administrator.</p>
    pub fn include_member_accounts(mut self, input: bool) -> Self {
        self.include_member_accounts = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to enroll member accounts of the organization if the account is the management account or delegated administrator.</p>
    pub fn set_include_member_accounts(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_member_accounts = input;
        self
    }
    /// <p>Indicates whether to enroll member accounts of the organization if the account is the management account or delegated administrator.</p>
    pub fn get_include_member_accounts(&self) -> &::std::option::Option<bool> {
        &self.include_member_accounts
    }
    /// Consumes the builder and constructs a [`UpdateEnrollmentStatusInput`](crate::operation::update_enrollment_status::UpdateEnrollmentStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_enrollment_status::UpdateEnrollmentStatusInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_enrollment_status::UpdateEnrollmentStatusInput {
            status: self.status,
            include_member_accounts: self.include_member_accounts,
        })
    }
}
