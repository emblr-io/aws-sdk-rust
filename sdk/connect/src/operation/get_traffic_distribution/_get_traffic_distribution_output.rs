// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTrafficDistributionOutput {
    /// <p>The distribution of traffic between the instance and its replicas.</p>
    pub telephony_config: ::std::option::Option<crate::types::TelephonyConfig>,
    /// <p>The identifier of the traffic distribution group. This can be the ID or the ARN if the API is being called in the Region where the traffic distribution group was created. The ARN must be provided if the call is from the replicated Region.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the traffic distribution group.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The distribution that determines which Amazon Web Services Regions should be used to sign in agents in to both the instance and its replica(s).</p>
    pub sign_in_config: ::std::option::Option<crate::types::SignInConfig>,
    /// <p>The distribution of agents between the instance and its replica(s).</p>
    pub agent_config: ::std::option::Option<crate::types::AgentConfig>,
    _request_id: Option<String>,
}
impl GetTrafficDistributionOutput {
    /// <p>The distribution of traffic between the instance and its replicas.</p>
    pub fn telephony_config(&self) -> ::std::option::Option<&crate::types::TelephonyConfig> {
        self.telephony_config.as_ref()
    }
    /// <p>The identifier of the traffic distribution group. This can be the ID or the ARN if the API is being called in the Region where the traffic distribution group was created. The ARN must be provided if the call is from the replicated Region.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the traffic distribution group.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The distribution that determines which Amazon Web Services Regions should be used to sign in agents in to both the instance and its replica(s).</p>
    pub fn sign_in_config(&self) -> ::std::option::Option<&crate::types::SignInConfig> {
        self.sign_in_config.as_ref()
    }
    /// <p>The distribution of agents between the instance and its replica(s).</p>
    pub fn agent_config(&self) -> ::std::option::Option<&crate::types::AgentConfig> {
        self.agent_config.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetTrafficDistributionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTrafficDistributionOutput {
    /// Creates a new builder-style object to manufacture [`GetTrafficDistributionOutput`](crate::operation::get_traffic_distribution::GetTrafficDistributionOutput).
    pub fn builder() -> crate::operation::get_traffic_distribution::builders::GetTrafficDistributionOutputBuilder {
        crate::operation::get_traffic_distribution::builders::GetTrafficDistributionOutputBuilder::default()
    }
}

/// A builder for [`GetTrafficDistributionOutput`](crate::operation::get_traffic_distribution::GetTrafficDistributionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTrafficDistributionOutputBuilder {
    pub(crate) telephony_config: ::std::option::Option<crate::types::TelephonyConfig>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) sign_in_config: ::std::option::Option<crate::types::SignInConfig>,
    pub(crate) agent_config: ::std::option::Option<crate::types::AgentConfig>,
    _request_id: Option<String>,
}
impl GetTrafficDistributionOutputBuilder {
    /// <p>The distribution of traffic between the instance and its replicas.</p>
    pub fn telephony_config(mut self, input: crate::types::TelephonyConfig) -> Self {
        self.telephony_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The distribution of traffic between the instance and its replicas.</p>
    pub fn set_telephony_config(mut self, input: ::std::option::Option<crate::types::TelephonyConfig>) -> Self {
        self.telephony_config = input;
        self
    }
    /// <p>The distribution of traffic between the instance and its replicas.</p>
    pub fn get_telephony_config(&self) -> &::std::option::Option<crate::types::TelephonyConfig> {
        &self.telephony_config
    }
    /// <p>The identifier of the traffic distribution group. This can be the ID or the ARN if the API is being called in the Region where the traffic distribution group was created. The ARN must be provided if the call is from the replicated Region.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the traffic distribution group. This can be the ID or the ARN if the API is being called in the Region where the traffic distribution group was created. The ARN must be provided if the call is from the replicated Region.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the traffic distribution group. This can be the ID or the ARN if the API is being called in the Region where the traffic distribution group was created. The ARN must be provided if the call is from the replicated Region.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the traffic distribution group.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the traffic distribution group.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the traffic distribution group.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The distribution that determines which Amazon Web Services Regions should be used to sign in agents in to both the instance and its replica(s).</p>
    pub fn sign_in_config(mut self, input: crate::types::SignInConfig) -> Self {
        self.sign_in_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The distribution that determines which Amazon Web Services Regions should be used to sign in agents in to both the instance and its replica(s).</p>
    pub fn set_sign_in_config(mut self, input: ::std::option::Option<crate::types::SignInConfig>) -> Self {
        self.sign_in_config = input;
        self
    }
    /// <p>The distribution that determines which Amazon Web Services Regions should be used to sign in agents in to both the instance and its replica(s).</p>
    pub fn get_sign_in_config(&self) -> &::std::option::Option<crate::types::SignInConfig> {
        &self.sign_in_config
    }
    /// <p>The distribution of agents between the instance and its replica(s).</p>
    pub fn agent_config(mut self, input: crate::types::AgentConfig) -> Self {
        self.agent_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The distribution of agents between the instance and its replica(s).</p>
    pub fn set_agent_config(mut self, input: ::std::option::Option<crate::types::AgentConfig>) -> Self {
        self.agent_config = input;
        self
    }
    /// <p>The distribution of agents between the instance and its replica(s).</p>
    pub fn get_agent_config(&self) -> &::std::option::Option<crate::types::AgentConfig> {
        &self.agent_config
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTrafficDistributionOutput`](crate::operation::get_traffic_distribution::GetTrafficDistributionOutput).
    pub fn build(self) -> crate::operation::get_traffic_distribution::GetTrafficDistributionOutput {
        crate::operation::get_traffic_distribution::GetTrafficDistributionOutput {
            telephony_config: self.telephony_config,
            id: self.id,
            arn: self.arn,
            sign_in_config: self.sign_in_config,
            agent_config: self.agent_config,
            _request_id: self._request_id,
        }
    }
}
