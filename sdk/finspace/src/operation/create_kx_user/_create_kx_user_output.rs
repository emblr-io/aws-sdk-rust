// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateKxUserOutput {
    /// <p>A unique identifier for the user.</p>
    pub user_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) that identifies the user. For more information about ARNs and how to use ARNs in policies, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html">IAM Identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub user_arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the kdb environment.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The IAM role ARN that will be associated with the user.</p>
    pub iam_role: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateKxUserOutput {
    /// <p>A unique identifier for the user.</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the user. For more information about ARNs and how to use ARNs in policies, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html">IAM Identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn user_arn(&self) -> ::std::option::Option<&str> {
        self.user_arn.as_deref()
    }
    /// <p>A unique identifier for the kdb environment.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>The IAM role ARN that will be associated with the user.</p>
    pub fn iam_role(&self) -> ::std::option::Option<&str> {
        self.iam_role.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateKxUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateKxUserOutput {
    /// Creates a new builder-style object to manufacture [`CreateKxUserOutput`](crate::operation::create_kx_user::CreateKxUserOutput).
    pub fn builder() -> crate::operation::create_kx_user::builders::CreateKxUserOutputBuilder {
        crate::operation::create_kx_user::builders::CreateKxUserOutputBuilder::default()
    }
}

/// A builder for [`CreateKxUserOutput`](crate::operation::create_kx_user::CreateKxUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateKxUserOutputBuilder {
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
    pub(crate) user_arn: ::std::option::Option<::std::string::String>,
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) iam_role: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateKxUserOutputBuilder {
    /// <p>A unique identifier for the user.</p>
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the user.</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>A unique identifier for the user.</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the user. For more information about ARNs and how to use ARNs in policies, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html">IAM Identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn user_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the user. For more information about ARNs and how to use ARNs in policies, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html">IAM Identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn set_user_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the user. For more information about ARNs and how to use ARNs in policies, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html">IAM Identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn get_user_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_arn
    }
    /// <p>A unique identifier for the kdb environment.</p>
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the kdb environment.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>A unique identifier for the kdb environment.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// <p>The IAM role ARN that will be associated with the user.</p>
    pub fn iam_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role ARN that will be associated with the user.</p>
    pub fn set_iam_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role = input;
        self
    }
    /// <p>The IAM role ARN that will be associated with the user.</p>
    pub fn get_iam_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateKxUserOutput`](crate::operation::create_kx_user::CreateKxUserOutput).
    pub fn build(self) -> crate::operation::create_kx_user::CreateKxUserOutput {
        crate::operation::create_kx_user::CreateKxUserOutput {
            user_name: self.user_name,
            user_arn: self.user_arn,
            environment_id: self.environment_id,
            iam_role: self.iam_role,
            _request_id: self._request_id,
        }
    }
}
