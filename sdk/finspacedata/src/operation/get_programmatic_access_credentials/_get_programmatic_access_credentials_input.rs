// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Request for GetProgrammaticAccessCredentials operation
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetProgrammaticAccessCredentialsInput {
    /// <p>The time duration in which the credentials remain valid.</p>
    pub duration_in_minutes: ::std::option::Option<i64>,
    /// <p>The FinSpace environment identifier.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
}
impl GetProgrammaticAccessCredentialsInput {
    /// <p>The time duration in which the credentials remain valid.</p>
    pub fn duration_in_minutes(&self) -> ::std::option::Option<i64> {
        self.duration_in_minutes
    }
    /// <p>The FinSpace environment identifier.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
}
impl GetProgrammaticAccessCredentialsInput {
    /// Creates a new builder-style object to manufacture [`GetProgrammaticAccessCredentialsInput`](crate::operation::get_programmatic_access_credentials::GetProgrammaticAccessCredentialsInput).
    pub fn builder() -> crate::operation::get_programmatic_access_credentials::builders::GetProgrammaticAccessCredentialsInputBuilder {
        crate::operation::get_programmatic_access_credentials::builders::GetProgrammaticAccessCredentialsInputBuilder::default()
    }
}

/// A builder for [`GetProgrammaticAccessCredentialsInput`](crate::operation::get_programmatic_access_credentials::GetProgrammaticAccessCredentialsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetProgrammaticAccessCredentialsInputBuilder {
    pub(crate) duration_in_minutes: ::std::option::Option<i64>,
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
}
impl GetProgrammaticAccessCredentialsInputBuilder {
    /// <p>The time duration in which the credentials remain valid.</p>
    pub fn duration_in_minutes(mut self, input: i64) -> Self {
        self.duration_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time duration in which the credentials remain valid.</p>
    pub fn set_duration_in_minutes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.duration_in_minutes = input;
        self
    }
    /// <p>The time duration in which the credentials remain valid.</p>
    pub fn get_duration_in_minutes(&self) -> &::std::option::Option<i64> {
        &self.duration_in_minutes
    }
    /// <p>The FinSpace environment identifier.</p>
    /// This field is required.
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The FinSpace environment identifier.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>The FinSpace environment identifier.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// Consumes the builder and constructs a [`GetProgrammaticAccessCredentialsInput`](crate::operation::get_programmatic_access_credentials::GetProgrammaticAccessCredentialsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_programmatic_access_credentials::GetProgrammaticAccessCredentialsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_programmatic_access_credentials::GetProgrammaticAccessCredentialsInput {
                duration_in_minutes: self.duration_in_minutes,
                environment_id: self.environment_id,
            },
        )
    }
}
