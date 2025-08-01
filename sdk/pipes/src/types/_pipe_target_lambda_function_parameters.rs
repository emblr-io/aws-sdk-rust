// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for using a Lambda function as a target.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PipeTargetLambdaFunctionParameters {
    /// <p>Specify whether to invoke the function synchronously or asynchronously.</p>
    /// <ul>
    /// <li>
    /// <p><code>REQUEST_RESPONSE</code> (default) - Invoke synchronously. This corresponds to the <code>RequestResponse</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// <li>
    /// <p><code>FIRE_AND_FORGET</code> - Invoke asynchronously. This corresponds to the <code>Event</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html#pipes-invocation">Invocation types</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub invocation_type: ::std::option::Option<crate::types::PipeTargetInvocationType>,
}
impl PipeTargetLambdaFunctionParameters {
    /// <p>Specify whether to invoke the function synchronously or asynchronously.</p>
    /// <ul>
    /// <li>
    /// <p><code>REQUEST_RESPONSE</code> (default) - Invoke synchronously. This corresponds to the <code>RequestResponse</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// <li>
    /// <p><code>FIRE_AND_FORGET</code> - Invoke asynchronously. This corresponds to the <code>Event</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html#pipes-invocation">Invocation types</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub fn invocation_type(&self) -> ::std::option::Option<&crate::types::PipeTargetInvocationType> {
        self.invocation_type.as_ref()
    }
}
impl PipeTargetLambdaFunctionParameters {
    /// Creates a new builder-style object to manufacture [`PipeTargetLambdaFunctionParameters`](crate::types::PipeTargetLambdaFunctionParameters).
    pub fn builder() -> crate::types::builders::PipeTargetLambdaFunctionParametersBuilder {
        crate::types::builders::PipeTargetLambdaFunctionParametersBuilder::default()
    }
}

/// A builder for [`PipeTargetLambdaFunctionParameters`](crate::types::PipeTargetLambdaFunctionParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PipeTargetLambdaFunctionParametersBuilder {
    pub(crate) invocation_type: ::std::option::Option<crate::types::PipeTargetInvocationType>,
}
impl PipeTargetLambdaFunctionParametersBuilder {
    /// <p>Specify whether to invoke the function synchronously or asynchronously.</p>
    /// <ul>
    /// <li>
    /// <p><code>REQUEST_RESPONSE</code> (default) - Invoke synchronously. This corresponds to the <code>RequestResponse</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// <li>
    /// <p><code>FIRE_AND_FORGET</code> - Invoke asynchronously. This corresponds to the <code>Event</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html#pipes-invocation">Invocation types</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub fn invocation_type(mut self, input: crate::types::PipeTargetInvocationType) -> Self {
        self.invocation_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify whether to invoke the function synchronously or asynchronously.</p>
    /// <ul>
    /// <li>
    /// <p><code>REQUEST_RESPONSE</code> (default) - Invoke synchronously. This corresponds to the <code>RequestResponse</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// <li>
    /// <p><code>FIRE_AND_FORGET</code> - Invoke asynchronously. This corresponds to the <code>Event</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html#pipes-invocation">Invocation types</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub fn set_invocation_type(mut self, input: ::std::option::Option<crate::types::PipeTargetInvocationType>) -> Self {
        self.invocation_type = input;
        self
    }
    /// <p>Specify whether to invoke the function synchronously or asynchronously.</p>
    /// <ul>
    /// <li>
    /// <p><code>REQUEST_RESPONSE</code> (default) - Invoke synchronously. This corresponds to the <code>RequestResponse</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// <li>
    /// <p><code>FIRE_AND_FORGET</code> - Invoke asynchronously. This corresponds to the <code>Event</code> option in the <code>InvocationType</code> parameter for the Lambda <a href="https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html#API_Invoke_RequestSyntax">Invoke</a> API.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html#pipes-invocation">Invocation types</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub fn get_invocation_type(&self) -> &::std::option::Option<crate::types::PipeTargetInvocationType> {
        &self.invocation_type
    }
    /// Consumes the builder and constructs a [`PipeTargetLambdaFunctionParameters`](crate::types::PipeTargetLambdaFunctionParameters).
    pub fn build(self) -> crate::types::PipeTargetLambdaFunctionParameters {
        crate::types::PipeTargetLambdaFunctionParameters {
            invocation_type: self.invocation_type,
        }
    }
}
