// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssumeRootInput {
    /// <p>The member account principal ARN or account ID.</p>
    pub target_principal: ::std::option::Option<::std::string::String>,
    /// <p>The identity based policy that scopes the session to the privileged tasks that can be performed. You can use one of following Amazon Web Services managed policies to scope root session actions.</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMAuditRootUserCredentials">IAMAuditRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMCreateRootUserPassword">IAMCreateRootUserPassword</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMDeleteRootUserCredentials">IAMDeleteRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-S3UnlockBucketPolicy">S3UnlockBucketPolicy</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-SQSUnlockQueuePolicy">SQSUnlockQueuePolicy</a></p></li>
    /// </ul>
    pub task_policy_arn: ::std::option::Option<crate::types::PolicyDescriptorType>,
    /// <p>The duration, in seconds, of the privileged session. The value can range from 0 seconds up to the maximum session duration of 900 seconds (15 minutes). If you specify a value higher than this setting, the operation fails.</p>
    /// <p>By default, the value is set to <code>900</code> seconds.</p>
    pub duration_seconds: ::std::option::Option<i32>,
}
impl AssumeRootInput {
    /// <p>The member account principal ARN or account ID.</p>
    pub fn target_principal(&self) -> ::std::option::Option<&str> {
        self.target_principal.as_deref()
    }
    /// <p>The identity based policy that scopes the session to the privileged tasks that can be performed. You can use one of following Amazon Web Services managed policies to scope root session actions.</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMAuditRootUserCredentials">IAMAuditRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMCreateRootUserPassword">IAMCreateRootUserPassword</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMDeleteRootUserCredentials">IAMDeleteRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-S3UnlockBucketPolicy">S3UnlockBucketPolicy</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-SQSUnlockQueuePolicy">SQSUnlockQueuePolicy</a></p></li>
    /// </ul>
    pub fn task_policy_arn(&self) -> ::std::option::Option<&crate::types::PolicyDescriptorType> {
        self.task_policy_arn.as_ref()
    }
    /// <p>The duration, in seconds, of the privileged session. The value can range from 0 seconds up to the maximum session duration of 900 seconds (15 minutes). If you specify a value higher than this setting, the operation fails.</p>
    /// <p>By default, the value is set to <code>900</code> seconds.</p>
    pub fn duration_seconds(&self) -> ::std::option::Option<i32> {
        self.duration_seconds
    }
}
impl AssumeRootInput {
    /// Creates a new builder-style object to manufacture [`AssumeRootInput`](crate::operation::assume_root::AssumeRootInput).
    pub fn builder() -> crate::operation::assume_root::builders::AssumeRootInputBuilder {
        crate::operation::assume_root::builders::AssumeRootInputBuilder::default()
    }
}

/// A builder for [`AssumeRootInput`](crate::operation::assume_root::AssumeRootInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssumeRootInputBuilder {
    pub(crate) target_principal: ::std::option::Option<::std::string::String>,
    pub(crate) task_policy_arn: ::std::option::Option<crate::types::PolicyDescriptorType>,
    pub(crate) duration_seconds: ::std::option::Option<i32>,
}
impl AssumeRootInputBuilder {
    /// <p>The member account principal ARN or account ID.</p>
    /// This field is required.
    pub fn target_principal(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_principal = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The member account principal ARN or account ID.</p>
    pub fn set_target_principal(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_principal = input;
        self
    }
    /// <p>The member account principal ARN or account ID.</p>
    pub fn get_target_principal(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_principal
    }
    /// <p>The identity based policy that scopes the session to the privileged tasks that can be performed. You can use one of following Amazon Web Services managed policies to scope root session actions.</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMAuditRootUserCredentials">IAMAuditRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMCreateRootUserPassword">IAMCreateRootUserPassword</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMDeleteRootUserCredentials">IAMDeleteRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-S3UnlockBucketPolicy">S3UnlockBucketPolicy</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-SQSUnlockQueuePolicy">SQSUnlockQueuePolicy</a></p></li>
    /// </ul>
    /// This field is required.
    pub fn task_policy_arn(mut self, input: crate::types::PolicyDescriptorType) -> Self {
        self.task_policy_arn = ::std::option::Option::Some(input);
        self
    }
    /// <p>The identity based policy that scopes the session to the privileged tasks that can be performed. You can use one of following Amazon Web Services managed policies to scope root session actions.</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMAuditRootUserCredentials">IAMAuditRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMCreateRootUserPassword">IAMCreateRootUserPassword</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMDeleteRootUserCredentials">IAMDeleteRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-S3UnlockBucketPolicy">S3UnlockBucketPolicy</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-SQSUnlockQueuePolicy">SQSUnlockQueuePolicy</a></p></li>
    /// </ul>
    pub fn set_task_policy_arn(mut self, input: ::std::option::Option<crate::types::PolicyDescriptorType>) -> Self {
        self.task_policy_arn = input;
        self
    }
    /// <p>The identity based policy that scopes the session to the privileged tasks that can be performed. You can use one of following Amazon Web Services managed policies to scope root session actions.</p>
    /// <ul>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMAuditRootUserCredentials">IAMAuditRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMCreateRootUserPassword">IAMCreateRootUserPassword</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMDeleteRootUserCredentials">IAMDeleteRootUserCredentials</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-S3UnlockBucketPolicy">S3UnlockBucketPolicy</a></p></li>
    /// <li>
    /// <p><a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-SQSUnlockQueuePolicy">SQSUnlockQueuePolicy</a></p></li>
    /// </ul>
    pub fn get_task_policy_arn(&self) -> &::std::option::Option<crate::types::PolicyDescriptorType> {
        &self.task_policy_arn
    }
    /// <p>The duration, in seconds, of the privileged session. The value can range from 0 seconds up to the maximum session duration of 900 seconds (15 minutes). If you specify a value higher than this setting, the operation fails.</p>
    /// <p>By default, the value is set to <code>900</code> seconds.</p>
    pub fn duration_seconds(mut self, input: i32) -> Self {
        self.duration_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration, in seconds, of the privileged session. The value can range from 0 seconds up to the maximum session duration of 900 seconds (15 minutes). If you specify a value higher than this setting, the operation fails.</p>
    /// <p>By default, the value is set to <code>900</code> seconds.</p>
    pub fn set_duration_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.duration_seconds = input;
        self
    }
    /// <p>The duration, in seconds, of the privileged session. The value can range from 0 seconds up to the maximum session duration of 900 seconds (15 minutes). If you specify a value higher than this setting, the operation fails.</p>
    /// <p>By default, the value is set to <code>900</code> seconds.</p>
    pub fn get_duration_seconds(&self) -> &::std::option::Option<i32> {
        &self.duration_seconds
    }
    /// Consumes the builder and constructs a [`AssumeRootInput`](crate::operation::assume_root::AssumeRootInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::assume_root::AssumeRootInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::assume_root::AssumeRootInput {
            target_principal: self.target_principal,
            task_policy_arn: self.task_policy_arn,
            duration_seconds: self.duration_seconds,
        })
    }
}
