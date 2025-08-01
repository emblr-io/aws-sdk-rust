// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddPermissionInput {
    /// <p>The name or ARN of the Lambda function, version, or alias.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code> (name-only), <code>my-function:v1</code> (with alias).</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    pub function_name: ::std::option::Option<::std::string::String>,
    /// <p>A statement identifier that differentiates the statement from others in the same policy.</p>
    pub statement_id: ::std::option::Option<::std::string::String>,
    /// <p>The action that the principal can use on the function. For example, <code>lambda:InvokeFunction</code> or <code>lambda:GetFunction</code>.</p>
    pub action: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services service, Amazon Web Services account, IAM user, or IAM role that invokes the function. If you specify a service, use <code>SourceArn</code> or <code>SourceAccount</code> to limit who can invoke the function through that service.</p>
    pub principal: ::std::option::Option<::std::string::String>,
    /// <p>For Amazon Web Services services, the ARN of the Amazon Web Services resource that invokes the function. For example, an Amazon S3 bucket or Amazon SNS topic.</p>
    /// <p>Note that Lambda configures the comparison using the <code>StringLike</code> operator.</p>
    pub source_arn: ::std::option::Option<::std::string::String>,
    /// <p>For Amazon Web Services service, the ID of the Amazon Web Services account that owns the resource. Use this together with <code>SourceArn</code> to ensure that the specified account owns the resource. It is possible for an Amazon S3 bucket to be deleted by its owner and recreated by another account.</p>
    pub source_account: ::std::option::Option<::std::string::String>,
    /// <p>For Alexa Smart Home functions, a token that the invoker must supply.</p>
    pub event_source_token: ::std::option::Option<::std::string::String>,
    /// <p>Specify a version or alias to add permissions to a published version of the function.</p>
    pub qualifier: ::std::option::Option<::std::string::String>,
    /// <p>Update the policy only if the revision ID matches the ID that's specified. Use this option to avoid modifying a policy that has changed since you last read it.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for your organization in Organizations. Use this to grant permissions to all the Amazon Web Services accounts under this organization.</p>
    pub principal_org_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub function_url_auth_type: ::std::option::Option<crate::types::FunctionUrlAuthType>,
}
impl AddPermissionInput {
    /// <p>The name or ARN of the Lambda function, version, or alias.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code> (name-only), <code>my-function:v1</code> (with alias).</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    pub fn function_name(&self) -> ::std::option::Option<&str> {
        self.function_name.as_deref()
    }
    /// <p>A statement identifier that differentiates the statement from others in the same policy.</p>
    pub fn statement_id(&self) -> ::std::option::Option<&str> {
        self.statement_id.as_deref()
    }
    /// <p>The action that the principal can use on the function. For example, <code>lambda:InvokeFunction</code> or <code>lambda:GetFunction</code>.</p>
    pub fn action(&self) -> ::std::option::Option<&str> {
        self.action.as_deref()
    }
    /// <p>The Amazon Web Services service, Amazon Web Services account, IAM user, or IAM role that invokes the function. If you specify a service, use <code>SourceArn</code> or <code>SourceAccount</code> to limit who can invoke the function through that service.</p>
    pub fn principal(&self) -> ::std::option::Option<&str> {
        self.principal.as_deref()
    }
    /// <p>For Amazon Web Services services, the ARN of the Amazon Web Services resource that invokes the function. For example, an Amazon S3 bucket or Amazon SNS topic.</p>
    /// <p>Note that Lambda configures the comparison using the <code>StringLike</code> operator.</p>
    pub fn source_arn(&self) -> ::std::option::Option<&str> {
        self.source_arn.as_deref()
    }
    /// <p>For Amazon Web Services service, the ID of the Amazon Web Services account that owns the resource. Use this together with <code>SourceArn</code> to ensure that the specified account owns the resource. It is possible for an Amazon S3 bucket to be deleted by its owner and recreated by another account.</p>
    pub fn source_account(&self) -> ::std::option::Option<&str> {
        self.source_account.as_deref()
    }
    /// <p>For Alexa Smart Home functions, a token that the invoker must supply.</p>
    pub fn event_source_token(&self) -> ::std::option::Option<&str> {
        self.event_source_token.as_deref()
    }
    /// <p>Specify a version or alias to add permissions to a published version of the function.</p>
    pub fn qualifier(&self) -> ::std::option::Option<&str> {
        self.qualifier.as_deref()
    }
    /// <p>Update the policy only if the revision ID matches the ID that's specified. Use this option to avoid modifying a policy that has changed since you last read it.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
    /// <p>The identifier for your organization in Organizations. Use this to grant permissions to all the Amazon Web Services accounts under this organization.</p>
    pub fn principal_org_id(&self) -> ::std::option::Option<&str> {
        self.principal_org_id.as_deref()
    }
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub fn function_url_auth_type(&self) -> ::std::option::Option<&crate::types::FunctionUrlAuthType> {
        self.function_url_auth_type.as_ref()
    }
}
impl AddPermissionInput {
    /// Creates a new builder-style object to manufacture [`AddPermissionInput`](crate::operation::add_permission::AddPermissionInput).
    pub fn builder() -> crate::operation::add_permission::builders::AddPermissionInputBuilder {
        crate::operation::add_permission::builders::AddPermissionInputBuilder::default()
    }
}

/// A builder for [`AddPermissionInput`](crate::operation::add_permission::AddPermissionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddPermissionInputBuilder {
    pub(crate) function_name: ::std::option::Option<::std::string::String>,
    pub(crate) statement_id: ::std::option::Option<::std::string::String>,
    pub(crate) action: ::std::option::Option<::std::string::String>,
    pub(crate) principal: ::std::option::Option<::std::string::String>,
    pub(crate) source_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_account: ::std::option::Option<::std::string::String>,
    pub(crate) event_source_token: ::std::option::Option<::std::string::String>,
    pub(crate) qualifier: ::std::option::Option<::std::string::String>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal_org_id: ::std::option::Option<::std::string::String>,
    pub(crate) function_url_auth_type: ::std::option::Option<crate::types::FunctionUrlAuthType>,
}
impl AddPermissionInputBuilder {
    /// <p>The name or ARN of the Lambda function, version, or alias.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code> (name-only), <code>my-function:v1</code> (with alias).</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    /// This field is required.
    pub fn function_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the Lambda function, version, or alias.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code> (name-only), <code>my-function:v1</code> (with alias).</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    pub fn set_function_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function_name = input;
        self
    }
    /// <p>The name or ARN of the Lambda function, version, or alias.</p>
    /// <p class="title"><b>Name formats</b></p>
    /// <ul>
    /// <li>
    /// <p><b>Function name</b> – <code>my-function</code> (name-only), <code>my-function:v1</code> (with alias).</p></li>
    /// <li>
    /// <p><b>Function ARN</b> – <code>arn:aws:lambda:us-west-2:123456789012:function:my-function</code>.</p></li>
    /// <li>
    /// <p><b>Partial ARN</b> – <code>123456789012:function:my-function</code>.</p></li>
    /// </ul>
    /// <p>You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length.</p>
    pub fn get_function_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.function_name
    }
    /// <p>A statement identifier that differentiates the statement from others in the same policy.</p>
    /// This field is required.
    pub fn statement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.statement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A statement identifier that differentiates the statement from others in the same policy.</p>
    pub fn set_statement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.statement_id = input;
        self
    }
    /// <p>A statement identifier that differentiates the statement from others in the same policy.</p>
    pub fn get_statement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.statement_id
    }
    /// <p>The action that the principal can use on the function. For example, <code>lambda:InvokeFunction</code> or <code>lambda:GetFunction</code>.</p>
    /// This field is required.
    pub fn action(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The action that the principal can use on the function. For example, <code>lambda:InvokeFunction</code> or <code>lambda:GetFunction</code>.</p>
    pub fn set_action(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action = input;
        self
    }
    /// <p>The action that the principal can use on the function. For example, <code>lambda:InvokeFunction</code> or <code>lambda:GetFunction</code>.</p>
    pub fn get_action(&self) -> &::std::option::Option<::std::string::String> {
        &self.action
    }
    /// <p>The Amazon Web Services service, Amazon Web Services account, IAM user, or IAM role that invokes the function. If you specify a service, use <code>SourceArn</code> or <code>SourceAccount</code> to limit who can invoke the function through that service.</p>
    /// This field is required.
    pub fn principal(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services service, Amazon Web Services account, IAM user, or IAM role that invokes the function. If you specify a service, use <code>SourceArn</code> or <code>SourceAccount</code> to limit who can invoke the function through that service.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal = input;
        self
    }
    /// <p>The Amazon Web Services service, Amazon Web Services account, IAM user, or IAM role that invokes the function. If you specify a service, use <code>SourceArn</code> or <code>SourceAccount</code> to limit who can invoke the function through that service.</p>
    pub fn get_principal(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal
    }
    /// <p>For Amazon Web Services services, the ARN of the Amazon Web Services resource that invokes the function. For example, an Amazon S3 bucket or Amazon SNS topic.</p>
    /// <p>Note that Lambda configures the comparison using the <code>StringLike</code> operator.</p>
    pub fn source_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For Amazon Web Services services, the ARN of the Amazon Web Services resource that invokes the function. For example, an Amazon S3 bucket or Amazon SNS topic.</p>
    /// <p>Note that Lambda configures the comparison using the <code>StringLike</code> operator.</p>
    pub fn set_source_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_arn = input;
        self
    }
    /// <p>For Amazon Web Services services, the ARN of the Amazon Web Services resource that invokes the function. For example, an Amazon S3 bucket or Amazon SNS topic.</p>
    /// <p>Note that Lambda configures the comparison using the <code>StringLike</code> operator.</p>
    pub fn get_source_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_arn
    }
    /// <p>For Amazon Web Services service, the ID of the Amazon Web Services account that owns the resource. Use this together with <code>SourceArn</code> to ensure that the specified account owns the resource. It is possible for an Amazon S3 bucket to be deleted by its owner and recreated by another account.</p>
    pub fn source_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For Amazon Web Services service, the ID of the Amazon Web Services account that owns the resource. Use this together with <code>SourceArn</code> to ensure that the specified account owns the resource. It is possible for an Amazon S3 bucket to be deleted by its owner and recreated by another account.</p>
    pub fn set_source_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_account = input;
        self
    }
    /// <p>For Amazon Web Services service, the ID of the Amazon Web Services account that owns the resource. Use this together with <code>SourceArn</code> to ensure that the specified account owns the resource. It is possible for an Amazon S3 bucket to be deleted by its owner and recreated by another account.</p>
    pub fn get_source_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_account
    }
    /// <p>For Alexa Smart Home functions, a token that the invoker must supply.</p>
    pub fn event_source_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_source_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For Alexa Smart Home functions, a token that the invoker must supply.</p>
    pub fn set_event_source_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_source_token = input;
        self
    }
    /// <p>For Alexa Smart Home functions, a token that the invoker must supply.</p>
    pub fn get_event_source_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_source_token
    }
    /// <p>Specify a version or alias to add permissions to a published version of the function.</p>
    pub fn qualifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.qualifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify a version or alias to add permissions to a published version of the function.</p>
    pub fn set_qualifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.qualifier = input;
        self
    }
    /// <p>Specify a version or alias to add permissions to a published version of the function.</p>
    pub fn get_qualifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.qualifier
    }
    /// <p>Update the policy only if the revision ID matches the ID that's specified. Use this option to avoid modifying a policy that has changed since you last read it.</p>
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Update the policy only if the revision ID matches the ID that's specified. Use this option to avoid modifying a policy that has changed since you last read it.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>Update the policy only if the revision ID matches the ID that's specified. Use this option to avoid modifying a policy that has changed since you last read it.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// <p>The identifier for your organization in Organizations. Use this to grant permissions to all the Amazon Web Services accounts under this organization.</p>
    pub fn principal_org_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_org_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for your organization in Organizations. Use this to grant permissions to all the Amazon Web Services accounts under this organization.</p>
    pub fn set_principal_org_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_org_id = input;
        self
    }
    /// <p>The identifier for your organization in Organizations. Use this to grant permissions to all the Amazon Web Services accounts under this organization.</p>
    pub fn get_principal_org_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_org_id
    }
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub fn function_url_auth_type(mut self, input: crate::types::FunctionUrlAuthType) -> Self {
        self.function_url_auth_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub fn set_function_url_auth_type(mut self, input: ::std::option::Option<crate::types::FunctionUrlAuthType>) -> Self {
        self.function_url_auth_type = input;
        self
    }
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub fn get_function_url_auth_type(&self) -> &::std::option::Option<crate::types::FunctionUrlAuthType> {
        &self.function_url_auth_type
    }
    /// Consumes the builder and constructs a [`AddPermissionInput`](crate::operation::add_permission::AddPermissionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::add_permission::AddPermissionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::add_permission::AddPermissionInput {
            function_name: self.function_name,
            statement_id: self.statement_id,
            action: self.action,
            principal: self.principal,
            source_arn: self.source_arn,
            source_account: self.source_account,
            event_source_token: self.event_source_token,
            qualifier: self.qualifier,
            revision_id: self.revision_id,
            principal_org_id: self.principal_org_id,
            function_url_auth_type: self.function_url_auth_type,
        })
    }
}
