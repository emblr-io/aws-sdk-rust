// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateProjectMembershipInput {
    /// <p>The ID of the Amazon DataZone domain in which project membership is created.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the project for which this project membership was created.</p>
    pub project_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The project member whose project membership was created.</p>
    pub member: ::std::option::Option<crate::types::Member>,
    /// <p>The designation of the project membership.</p>
    pub designation: ::std::option::Option<crate::types::UserDesignation>,
}
impl CreateProjectMembershipInput {
    /// <p>The ID of the Amazon DataZone domain in which project membership is created.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The ID of the project for which this project membership was created.</p>
    pub fn project_identifier(&self) -> ::std::option::Option<&str> {
        self.project_identifier.as_deref()
    }
    /// <p>The project member whose project membership was created.</p>
    pub fn member(&self) -> ::std::option::Option<&crate::types::Member> {
        self.member.as_ref()
    }
    /// <p>The designation of the project membership.</p>
    pub fn designation(&self) -> ::std::option::Option<&crate::types::UserDesignation> {
        self.designation.as_ref()
    }
}
impl CreateProjectMembershipInput {
    /// Creates a new builder-style object to manufacture [`CreateProjectMembershipInput`](crate::operation::create_project_membership::CreateProjectMembershipInput).
    pub fn builder() -> crate::operation::create_project_membership::builders::CreateProjectMembershipInputBuilder {
        crate::operation::create_project_membership::builders::CreateProjectMembershipInputBuilder::default()
    }
}

/// A builder for [`CreateProjectMembershipInput`](crate::operation::create_project_membership::CreateProjectMembershipInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateProjectMembershipInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) project_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) member: ::std::option::Option<crate::types::Member>,
    pub(crate) designation: ::std::option::Option<crate::types::UserDesignation>,
}
impl CreateProjectMembershipInputBuilder {
    /// <p>The ID of the Amazon DataZone domain in which project membership is created.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which project membership is created.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain in which project membership is created.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The ID of the project for which this project membership was created.</p>
    /// This field is required.
    pub fn project_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the project for which this project membership was created.</p>
    pub fn set_project_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_identifier = input;
        self
    }
    /// <p>The ID of the project for which this project membership was created.</p>
    pub fn get_project_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_identifier
    }
    /// <p>The project member whose project membership was created.</p>
    /// This field is required.
    pub fn member(mut self, input: crate::types::Member) -> Self {
        self.member = ::std::option::Option::Some(input);
        self
    }
    /// <p>The project member whose project membership was created.</p>
    pub fn set_member(mut self, input: ::std::option::Option<crate::types::Member>) -> Self {
        self.member = input;
        self
    }
    /// <p>The project member whose project membership was created.</p>
    pub fn get_member(&self) -> &::std::option::Option<crate::types::Member> {
        &self.member
    }
    /// <p>The designation of the project membership.</p>
    /// This field is required.
    pub fn designation(mut self, input: crate::types::UserDesignation) -> Self {
        self.designation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The designation of the project membership.</p>
    pub fn set_designation(mut self, input: ::std::option::Option<crate::types::UserDesignation>) -> Self {
        self.designation = input;
        self
    }
    /// <p>The designation of the project membership.</p>
    pub fn get_designation(&self) -> &::std::option::Option<crate::types::UserDesignation> {
        &self.designation
    }
    /// Consumes the builder and constructs a [`CreateProjectMembershipInput`](crate::operation::create_project_membership::CreateProjectMembershipInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_project_membership::CreateProjectMembershipInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_project_membership::CreateProjectMembershipInput {
            domain_identifier: self.domain_identifier,
            project_identifier: self.project_identifier,
            member: self.member,
            designation: self.designation,
        })
    }
}
