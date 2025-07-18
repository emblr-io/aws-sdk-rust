// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A short description of a user pool.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UserPoolDescriptionType {
    /// <p>The user pool ID.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The user pool name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A collection of user pool Lambda triggers. Amazon Cognito invokes triggers at several possible stages of user pool operations. Triggers can modify the outcome of the operations that invoked them.</p>
    pub lambda_config: ::std::option::Option<crate::types::LambdaConfigType>,
    /// <p>The user pool status.</p>
    #[deprecated(note = "This property is no longer available.")]
    pub status: ::std::option::Option<crate::types::StatusType>,
    /// <p>The date and time when the item was modified. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time when the item was created. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl UserPoolDescriptionType {
    /// <p>The user pool ID.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The user pool name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A collection of user pool Lambda triggers. Amazon Cognito invokes triggers at several possible stages of user pool operations. Triggers can modify the outcome of the operations that invoked them.</p>
    pub fn lambda_config(&self) -> ::std::option::Option<&crate::types::LambdaConfigType> {
        self.lambda_config.as_ref()
    }
    /// <p>The user pool status.</p>
    #[deprecated(note = "This property is no longer available.")]
    pub fn status(&self) -> ::std::option::Option<&crate::types::StatusType> {
        self.status.as_ref()
    }
    /// <p>The date and time when the item was modified. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub fn last_modified_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_date.as_ref()
    }
    /// <p>The date and time when the item was created. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
}
impl UserPoolDescriptionType {
    /// Creates a new builder-style object to manufacture [`UserPoolDescriptionType`](crate::types::UserPoolDescriptionType).
    pub fn builder() -> crate::types::builders::UserPoolDescriptionTypeBuilder {
        crate::types::builders::UserPoolDescriptionTypeBuilder::default()
    }
}

/// A builder for [`UserPoolDescriptionType`](crate::types::UserPoolDescriptionType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UserPoolDescriptionTypeBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) lambda_config: ::std::option::Option<crate::types::LambdaConfigType>,
    pub(crate) status: ::std::option::Option<crate::types::StatusType>,
    pub(crate) last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl UserPoolDescriptionTypeBuilder {
    /// <p>The user pool ID.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user pool ID.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The user pool ID.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The user pool name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user pool name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The user pool name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A collection of user pool Lambda triggers. Amazon Cognito invokes triggers at several possible stages of user pool operations. Triggers can modify the outcome of the operations that invoked them.</p>
    pub fn lambda_config(mut self, input: crate::types::LambdaConfigType) -> Self {
        self.lambda_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>A collection of user pool Lambda triggers. Amazon Cognito invokes triggers at several possible stages of user pool operations. Triggers can modify the outcome of the operations that invoked them.</p>
    pub fn set_lambda_config(mut self, input: ::std::option::Option<crate::types::LambdaConfigType>) -> Self {
        self.lambda_config = input;
        self
    }
    /// <p>A collection of user pool Lambda triggers. Amazon Cognito invokes triggers at several possible stages of user pool operations. Triggers can modify the outcome of the operations that invoked them.</p>
    pub fn get_lambda_config(&self) -> &::std::option::Option<crate::types::LambdaConfigType> {
        &self.lambda_config
    }
    /// <p>The user pool status.</p>
    #[deprecated(note = "This property is no longer available.")]
    pub fn status(mut self, input: crate::types::StatusType) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The user pool status.</p>
    #[deprecated(note = "This property is no longer available.")]
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StatusType>) -> Self {
        self.status = input;
        self
    }
    /// <p>The user pool status.</p>
    #[deprecated(note = "This property is no longer available.")]
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StatusType> {
        &self.status
    }
    /// <p>The date and time when the item was modified. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub fn last_modified_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the item was modified. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub fn set_last_modified_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_date = input;
        self
    }
    /// <p>The date and time when the item was modified. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub fn get_last_modified_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_date
    }
    /// <p>The date and time when the item was created. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the item was created. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date and time when the item was created. Amazon Cognito returns this timestamp in UNIX epoch time format. Your SDK might render the output in a human-readable format like ISO 8601 or a Java <code>Date</code> object.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// Consumes the builder and constructs a [`UserPoolDescriptionType`](crate::types::UserPoolDescriptionType).
    pub fn build(self) -> crate::types::UserPoolDescriptionType {
        crate::types::UserPoolDescriptionType {
            id: self.id,
            name: self.name,
            lambda_config: self.lambda_config,
            status: self.status,
            last_modified_date: self.last_modified_date,
            creation_date: self.creation_date,
        }
    }
}
