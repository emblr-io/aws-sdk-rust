// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::deregister_targets::_deregister_targets_output::DeregisterTargetsOutputBuilder;

pub use crate::operation::deregister_targets::_deregister_targets_input::DeregisterTargetsInputBuilder;

impl crate::operation::deregister_targets::builders::DeregisterTargetsInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::deregister_targets::DeregisterTargetsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::deregister_targets::DeregisterTargetsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.deregister_targets();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `DeregisterTargets`.
///
/// <p>Deregisters the specified targets from the specified target group. After the targets are deregistered, they no longer receive traffic from the load balancer.</p>
/// <p>The load balancer stops sending requests to targets that are deregistering, but uses connection draining to ensure that in-flight traffic completes on the existing connections. This deregistration delay is configured by default but can be updated for each target group.</p>
/// <p>For more information, see the following:</p>
/// <ul>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html#deregistration-delay"> Deregistration delay</a> in the <i>Application Load Balancers User Guide</i></p></li>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html#deregistration-delay"> Deregistration delay</a> in the <i>Network Load Balancers User Guide</i></p></li>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/edit-target-group-attributes.html#deregistration-delay"> Deregistration delay</a> in the <i>Gateway Load Balancers User Guide</i></p></li>
/// </ul>
/// <p>Note: If the specified target does not exist, the action returns successfully.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct DeregisterTargetsFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::deregister_targets::builders::DeregisterTargetsInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::deregister_targets::DeregisterTargetsOutput,
        crate::operation::deregister_targets::DeregisterTargetsError,
    > for DeregisterTargetsFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::deregister_targets::DeregisterTargetsOutput,
            crate::operation::deregister_targets::DeregisterTargetsError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl DeregisterTargetsFluentBuilder {
    /// Creates a new `DeregisterTargetsFluentBuilder`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the DeregisterTargets as a reference.
    pub fn as_input(&self) -> &crate::operation::deregister_targets::builders::DeregisterTargetsInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::deregister_targets::DeregisterTargetsOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::deregister_targets::DeregisterTargetsError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::deregister_targets::DeregisterTargets::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::deregister_targets::DeregisterTargets::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::deregister_targets::DeregisterTargetsOutput,
        crate::operation::deregister_targets::DeregisterTargetsError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl ::std::convert::Into<crate::config::Builder>) -> Self {
        self.set_config_override(::std::option::Option::Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: ::std::option::Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target group.</p>
    pub fn target_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.target_group_arn(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target group.</p>
    pub fn set_target_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_target_group_arn(input);
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target group.</p>
    pub fn get_target_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_target_group_arn()
    }
    ///
    /// Appends an item to `Targets`.
    ///
    /// To override the contents of this collection use [`set_targets`](Self::set_targets).
    ///
    /// <p>The targets. If you specified a port override when you registered a target, you must specify both the target ID and the port when you deregister it.</p>
    pub fn targets(mut self, input: crate::types::TargetDescription) -> Self {
        self.inner = self.inner.targets(input);
        self
    }
    /// <p>The targets. If you specified a port override when you registered a target, you must specify both the target ID and the port when you deregister it.</p>
    pub fn set_targets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TargetDescription>>) -> Self {
        self.inner = self.inner.set_targets(input);
        self
    }
    /// <p>The targets. If you specified a port override when you registered a target, you must specify both the target ID and the port when you deregister it.</p>
    pub fn get_targets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TargetDescription>> {
        self.inner.get_targets()
    }
}
