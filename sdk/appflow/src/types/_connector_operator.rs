// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The operation to be performed on the provided source fields.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConnectorOperator {
    /// <p>The operation to be performed on the provided Amplitude source fields.</p>
    pub amplitude: ::std::option::Option<crate::types::AmplitudeConnectorOperator>,
    /// <p>The operation to be performed on the provided Datadog source fields.</p>
    pub datadog: ::std::option::Option<crate::types::DatadogConnectorOperator>,
    /// <p>The operation to be performed on the provided Dynatrace source fields.</p>
    pub dynatrace: ::std::option::Option<crate::types::DynatraceConnectorOperator>,
    /// <p>The operation to be performed on the provided Google Analytics source fields.</p>
    pub google_analytics: ::std::option::Option<crate::types::GoogleAnalyticsConnectorOperator>,
    /// <p>The operation to be performed on the provided Infor Nexus source fields.</p>
    pub infor_nexus: ::std::option::Option<crate::types::InforNexusConnectorOperator>,
    /// <p>The operation to be performed on the provided Marketo source fields.</p>
    pub marketo: ::std::option::Option<crate::types::MarketoConnectorOperator>,
    /// <p>The operation to be performed on the provided Amazon S3 source fields.</p>
    pub s3: ::std::option::Option<crate::types::S3ConnectorOperator>,
    /// <p>The operation to be performed on the provided Salesforce source fields.</p>
    pub salesforce: ::std::option::Option<crate::types::SalesforceConnectorOperator>,
    /// <p>The operation to be performed on the provided ServiceNow source fields.</p>
    pub service_now: ::std::option::Option<crate::types::ServiceNowConnectorOperator>,
    /// <p>The operation to be performed on the provided Singular source fields.</p>
    pub singular: ::std::option::Option<crate::types::SingularConnectorOperator>,
    /// <p>The operation to be performed on the provided Slack source fields.</p>
    pub slack: ::std::option::Option<crate::types::SlackConnectorOperator>,
    /// <p>The operation to be performed on the provided Trend Micro source fields.</p>
    pub trendmicro: ::std::option::Option<crate::types::TrendmicroConnectorOperator>,
    /// <p>The operation to be performed on the provided Veeva source fields.</p>
    pub veeva: ::std::option::Option<crate::types::VeevaConnectorOperator>,
    /// <p>The operation to be performed on the provided Zendesk source fields.</p>
    pub zendesk: ::std::option::Option<crate::types::ZendeskConnectorOperator>,
    /// <p>The operation to be performed on the provided SAPOData source fields.</p>
    pub sapo_data: ::std::option::Option<crate::types::SapoDataConnectorOperator>,
    /// <p>Operators supported by the custom connector.</p>
    pub custom_connector: ::std::option::Option<crate::types::Operator>,
    /// <p>The operation to be performed on the provided Salesforce Pardot source fields.</p>
    pub pardot: ::std::option::Option<crate::types::PardotConnectorOperator>,
}
impl ConnectorOperator {
    /// <p>The operation to be performed on the provided Amplitude source fields.</p>
    pub fn amplitude(&self) -> ::std::option::Option<&crate::types::AmplitudeConnectorOperator> {
        self.amplitude.as_ref()
    }
    /// <p>The operation to be performed on the provided Datadog source fields.</p>
    pub fn datadog(&self) -> ::std::option::Option<&crate::types::DatadogConnectorOperator> {
        self.datadog.as_ref()
    }
    /// <p>The operation to be performed on the provided Dynatrace source fields.</p>
    pub fn dynatrace(&self) -> ::std::option::Option<&crate::types::DynatraceConnectorOperator> {
        self.dynatrace.as_ref()
    }
    /// <p>The operation to be performed on the provided Google Analytics source fields.</p>
    pub fn google_analytics(&self) -> ::std::option::Option<&crate::types::GoogleAnalyticsConnectorOperator> {
        self.google_analytics.as_ref()
    }
    /// <p>The operation to be performed on the provided Infor Nexus source fields.</p>
    pub fn infor_nexus(&self) -> ::std::option::Option<&crate::types::InforNexusConnectorOperator> {
        self.infor_nexus.as_ref()
    }
    /// <p>The operation to be performed on the provided Marketo source fields.</p>
    pub fn marketo(&self) -> ::std::option::Option<&crate::types::MarketoConnectorOperator> {
        self.marketo.as_ref()
    }
    /// <p>The operation to be performed on the provided Amazon S3 source fields.</p>
    pub fn s3(&self) -> ::std::option::Option<&crate::types::S3ConnectorOperator> {
        self.s3.as_ref()
    }
    /// <p>The operation to be performed on the provided Salesforce source fields.</p>
    pub fn salesforce(&self) -> ::std::option::Option<&crate::types::SalesforceConnectorOperator> {
        self.salesforce.as_ref()
    }
    /// <p>The operation to be performed on the provided ServiceNow source fields.</p>
    pub fn service_now(&self) -> ::std::option::Option<&crate::types::ServiceNowConnectorOperator> {
        self.service_now.as_ref()
    }
    /// <p>The operation to be performed on the provided Singular source fields.</p>
    pub fn singular(&self) -> ::std::option::Option<&crate::types::SingularConnectorOperator> {
        self.singular.as_ref()
    }
    /// <p>The operation to be performed on the provided Slack source fields.</p>
    pub fn slack(&self) -> ::std::option::Option<&crate::types::SlackConnectorOperator> {
        self.slack.as_ref()
    }
    /// <p>The operation to be performed on the provided Trend Micro source fields.</p>
    pub fn trendmicro(&self) -> ::std::option::Option<&crate::types::TrendmicroConnectorOperator> {
        self.trendmicro.as_ref()
    }
    /// <p>The operation to be performed on the provided Veeva source fields.</p>
    pub fn veeva(&self) -> ::std::option::Option<&crate::types::VeevaConnectorOperator> {
        self.veeva.as_ref()
    }
    /// <p>The operation to be performed on the provided Zendesk source fields.</p>
    pub fn zendesk(&self) -> ::std::option::Option<&crate::types::ZendeskConnectorOperator> {
        self.zendesk.as_ref()
    }
    /// <p>The operation to be performed on the provided SAPOData source fields.</p>
    pub fn sapo_data(&self) -> ::std::option::Option<&crate::types::SapoDataConnectorOperator> {
        self.sapo_data.as_ref()
    }
    /// <p>Operators supported by the custom connector.</p>
    pub fn custom_connector(&self) -> ::std::option::Option<&crate::types::Operator> {
        self.custom_connector.as_ref()
    }
    /// <p>The operation to be performed on the provided Salesforce Pardot source fields.</p>
    pub fn pardot(&self) -> ::std::option::Option<&crate::types::PardotConnectorOperator> {
        self.pardot.as_ref()
    }
}
impl ConnectorOperator {
    /// Creates a new builder-style object to manufacture [`ConnectorOperator`](crate::types::ConnectorOperator).
    pub fn builder() -> crate::types::builders::ConnectorOperatorBuilder {
        crate::types::builders::ConnectorOperatorBuilder::default()
    }
}

/// A builder for [`ConnectorOperator`](crate::types::ConnectorOperator).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConnectorOperatorBuilder {
    pub(crate) amplitude: ::std::option::Option<crate::types::AmplitudeConnectorOperator>,
    pub(crate) datadog: ::std::option::Option<crate::types::DatadogConnectorOperator>,
    pub(crate) dynatrace: ::std::option::Option<crate::types::DynatraceConnectorOperator>,
    pub(crate) google_analytics: ::std::option::Option<crate::types::GoogleAnalyticsConnectorOperator>,
    pub(crate) infor_nexus: ::std::option::Option<crate::types::InforNexusConnectorOperator>,
    pub(crate) marketo: ::std::option::Option<crate::types::MarketoConnectorOperator>,
    pub(crate) s3: ::std::option::Option<crate::types::S3ConnectorOperator>,
    pub(crate) salesforce: ::std::option::Option<crate::types::SalesforceConnectorOperator>,
    pub(crate) service_now: ::std::option::Option<crate::types::ServiceNowConnectorOperator>,
    pub(crate) singular: ::std::option::Option<crate::types::SingularConnectorOperator>,
    pub(crate) slack: ::std::option::Option<crate::types::SlackConnectorOperator>,
    pub(crate) trendmicro: ::std::option::Option<crate::types::TrendmicroConnectorOperator>,
    pub(crate) veeva: ::std::option::Option<crate::types::VeevaConnectorOperator>,
    pub(crate) zendesk: ::std::option::Option<crate::types::ZendeskConnectorOperator>,
    pub(crate) sapo_data: ::std::option::Option<crate::types::SapoDataConnectorOperator>,
    pub(crate) custom_connector: ::std::option::Option<crate::types::Operator>,
    pub(crate) pardot: ::std::option::Option<crate::types::PardotConnectorOperator>,
}
impl ConnectorOperatorBuilder {
    /// <p>The operation to be performed on the provided Amplitude source fields.</p>
    pub fn amplitude(mut self, input: crate::types::AmplitudeConnectorOperator) -> Self {
        self.amplitude = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Amplitude source fields.</p>
    pub fn set_amplitude(mut self, input: ::std::option::Option<crate::types::AmplitudeConnectorOperator>) -> Self {
        self.amplitude = input;
        self
    }
    /// <p>The operation to be performed on the provided Amplitude source fields.</p>
    pub fn get_amplitude(&self) -> &::std::option::Option<crate::types::AmplitudeConnectorOperator> {
        &self.amplitude
    }
    /// <p>The operation to be performed on the provided Datadog source fields.</p>
    pub fn datadog(mut self, input: crate::types::DatadogConnectorOperator) -> Self {
        self.datadog = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Datadog source fields.</p>
    pub fn set_datadog(mut self, input: ::std::option::Option<crate::types::DatadogConnectorOperator>) -> Self {
        self.datadog = input;
        self
    }
    /// <p>The operation to be performed on the provided Datadog source fields.</p>
    pub fn get_datadog(&self) -> &::std::option::Option<crate::types::DatadogConnectorOperator> {
        &self.datadog
    }
    /// <p>The operation to be performed on the provided Dynatrace source fields.</p>
    pub fn dynatrace(mut self, input: crate::types::DynatraceConnectorOperator) -> Self {
        self.dynatrace = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Dynatrace source fields.</p>
    pub fn set_dynatrace(mut self, input: ::std::option::Option<crate::types::DynatraceConnectorOperator>) -> Self {
        self.dynatrace = input;
        self
    }
    /// <p>The operation to be performed on the provided Dynatrace source fields.</p>
    pub fn get_dynatrace(&self) -> &::std::option::Option<crate::types::DynatraceConnectorOperator> {
        &self.dynatrace
    }
    /// <p>The operation to be performed on the provided Google Analytics source fields.</p>
    pub fn google_analytics(mut self, input: crate::types::GoogleAnalyticsConnectorOperator) -> Self {
        self.google_analytics = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Google Analytics source fields.</p>
    pub fn set_google_analytics(mut self, input: ::std::option::Option<crate::types::GoogleAnalyticsConnectorOperator>) -> Self {
        self.google_analytics = input;
        self
    }
    /// <p>The operation to be performed on the provided Google Analytics source fields.</p>
    pub fn get_google_analytics(&self) -> &::std::option::Option<crate::types::GoogleAnalyticsConnectorOperator> {
        &self.google_analytics
    }
    /// <p>The operation to be performed on the provided Infor Nexus source fields.</p>
    pub fn infor_nexus(mut self, input: crate::types::InforNexusConnectorOperator) -> Self {
        self.infor_nexus = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Infor Nexus source fields.</p>
    pub fn set_infor_nexus(mut self, input: ::std::option::Option<crate::types::InforNexusConnectorOperator>) -> Self {
        self.infor_nexus = input;
        self
    }
    /// <p>The operation to be performed on the provided Infor Nexus source fields.</p>
    pub fn get_infor_nexus(&self) -> &::std::option::Option<crate::types::InforNexusConnectorOperator> {
        &self.infor_nexus
    }
    /// <p>The operation to be performed on the provided Marketo source fields.</p>
    pub fn marketo(mut self, input: crate::types::MarketoConnectorOperator) -> Self {
        self.marketo = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Marketo source fields.</p>
    pub fn set_marketo(mut self, input: ::std::option::Option<crate::types::MarketoConnectorOperator>) -> Self {
        self.marketo = input;
        self
    }
    /// <p>The operation to be performed on the provided Marketo source fields.</p>
    pub fn get_marketo(&self) -> &::std::option::Option<crate::types::MarketoConnectorOperator> {
        &self.marketo
    }
    /// <p>The operation to be performed on the provided Amazon S3 source fields.</p>
    pub fn s3(mut self, input: crate::types::S3ConnectorOperator) -> Self {
        self.s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Amazon S3 source fields.</p>
    pub fn set_s3(mut self, input: ::std::option::Option<crate::types::S3ConnectorOperator>) -> Self {
        self.s3 = input;
        self
    }
    /// <p>The operation to be performed on the provided Amazon S3 source fields.</p>
    pub fn get_s3(&self) -> &::std::option::Option<crate::types::S3ConnectorOperator> {
        &self.s3
    }
    /// <p>The operation to be performed on the provided Salesforce source fields.</p>
    pub fn salesforce(mut self, input: crate::types::SalesforceConnectorOperator) -> Self {
        self.salesforce = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Salesforce source fields.</p>
    pub fn set_salesforce(mut self, input: ::std::option::Option<crate::types::SalesforceConnectorOperator>) -> Self {
        self.salesforce = input;
        self
    }
    /// <p>The operation to be performed on the provided Salesforce source fields.</p>
    pub fn get_salesforce(&self) -> &::std::option::Option<crate::types::SalesforceConnectorOperator> {
        &self.salesforce
    }
    /// <p>The operation to be performed on the provided ServiceNow source fields.</p>
    pub fn service_now(mut self, input: crate::types::ServiceNowConnectorOperator) -> Self {
        self.service_now = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided ServiceNow source fields.</p>
    pub fn set_service_now(mut self, input: ::std::option::Option<crate::types::ServiceNowConnectorOperator>) -> Self {
        self.service_now = input;
        self
    }
    /// <p>The operation to be performed on the provided ServiceNow source fields.</p>
    pub fn get_service_now(&self) -> &::std::option::Option<crate::types::ServiceNowConnectorOperator> {
        &self.service_now
    }
    /// <p>The operation to be performed on the provided Singular source fields.</p>
    pub fn singular(mut self, input: crate::types::SingularConnectorOperator) -> Self {
        self.singular = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Singular source fields.</p>
    pub fn set_singular(mut self, input: ::std::option::Option<crate::types::SingularConnectorOperator>) -> Self {
        self.singular = input;
        self
    }
    /// <p>The operation to be performed on the provided Singular source fields.</p>
    pub fn get_singular(&self) -> &::std::option::Option<crate::types::SingularConnectorOperator> {
        &self.singular
    }
    /// <p>The operation to be performed on the provided Slack source fields.</p>
    pub fn slack(mut self, input: crate::types::SlackConnectorOperator) -> Self {
        self.slack = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Slack source fields.</p>
    pub fn set_slack(mut self, input: ::std::option::Option<crate::types::SlackConnectorOperator>) -> Self {
        self.slack = input;
        self
    }
    /// <p>The operation to be performed on the provided Slack source fields.</p>
    pub fn get_slack(&self) -> &::std::option::Option<crate::types::SlackConnectorOperator> {
        &self.slack
    }
    /// <p>The operation to be performed on the provided Trend Micro source fields.</p>
    pub fn trendmicro(mut self, input: crate::types::TrendmicroConnectorOperator) -> Self {
        self.trendmicro = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Trend Micro source fields.</p>
    pub fn set_trendmicro(mut self, input: ::std::option::Option<crate::types::TrendmicroConnectorOperator>) -> Self {
        self.trendmicro = input;
        self
    }
    /// <p>The operation to be performed on the provided Trend Micro source fields.</p>
    pub fn get_trendmicro(&self) -> &::std::option::Option<crate::types::TrendmicroConnectorOperator> {
        &self.trendmicro
    }
    /// <p>The operation to be performed on the provided Veeva source fields.</p>
    pub fn veeva(mut self, input: crate::types::VeevaConnectorOperator) -> Self {
        self.veeva = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Veeva source fields.</p>
    pub fn set_veeva(mut self, input: ::std::option::Option<crate::types::VeevaConnectorOperator>) -> Self {
        self.veeva = input;
        self
    }
    /// <p>The operation to be performed on the provided Veeva source fields.</p>
    pub fn get_veeva(&self) -> &::std::option::Option<crate::types::VeevaConnectorOperator> {
        &self.veeva
    }
    /// <p>The operation to be performed on the provided Zendesk source fields.</p>
    pub fn zendesk(mut self, input: crate::types::ZendeskConnectorOperator) -> Self {
        self.zendesk = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Zendesk source fields.</p>
    pub fn set_zendesk(mut self, input: ::std::option::Option<crate::types::ZendeskConnectorOperator>) -> Self {
        self.zendesk = input;
        self
    }
    /// <p>The operation to be performed on the provided Zendesk source fields.</p>
    pub fn get_zendesk(&self) -> &::std::option::Option<crate::types::ZendeskConnectorOperator> {
        &self.zendesk
    }
    /// <p>The operation to be performed on the provided SAPOData source fields.</p>
    pub fn sapo_data(mut self, input: crate::types::SapoDataConnectorOperator) -> Self {
        self.sapo_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided SAPOData source fields.</p>
    pub fn set_sapo_data(mut self, input: ::std::option::Option<crate::types::SapoDataConnectorOperator>) -> Self {
        self.sapo_data = input;
        self
    }
    /// <p>The operation to be performed on the provided SAPOData source fields.</p>
    pub fn get_sapo_data(&self) -> &::std::option::Option<crate::types::SapoDataConnectorOperator> {
        &self.sapo_data
    }
    /// <p>Operators supported by the custom connector.</p>
    pub fn custom_connector(mut self, input: crate::types::Operator) -> Self {
        self.custom_connector = ::std::option::Option::Some(input);
        self
    }
    /// <p>Operators supported by the custom connector.</p>
    pub fn set_custom_connector(mut self, input: ::std::option::Option<crate::types::Operator>) -> Self {
        self.custom_connector = input;
        self
    }
    /// <p>Operators supported by the custom connector.</p>
    pub fn get_custom_connector(&self) -> &::std::option::Option<crate::types::Operator> {
        &self.custom_connector
    }
    /// <p>The operation to be performed on the provided Salesforce Pardot source fields.</p>
    pub fn pardot(mut self, input: crate::types::PardotConnectorOperator) -> Self {
        self.pardot = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to be performed on the provided Salesforce Pardot source fields.</p>
    pub fn set_pardot(mut self, input: ::std::option::Option<crate::types::PardotConnectorOperator>) -> Self {
        self.pardot = input;
        self
    }
    /// <p>The operation to be performed on the provided Salesforce Pardot source fields.</p>
    pub fn get_pardot(&self) -> &::std::option::Option<crate::types::PardotConnectorOperator> {
        &self.pardot
    }
    /// Consumes the builder and constructs a [`ConnectorOperator`](crate::types::ConnectorOperator).
    pub fn build(self) -> crate::types::ConnectorOperator {
        crate::types::ConnectorOperator {
            amplitude: self.amplitude,
            datadog: self.datadog,
            dynatrace: self.dynatrace,
            google_analytics: self.google_analytics,
            infor_nexus: self.infor_nexus,
            marketo: self.marketo,
            s3: self.s3,
            salesforce: self.salesforce,
            service_now: self.service_now,
            singular: self.singular,
            slack: self.slack,
            trendmicro: self.trendmicro,
            veeva: self.veeva,
            zendesk: self.zendesk,
            sapo_data: self.sapo_data,
            custom_connector: self.custom_connector,
            pardot: self.pardot,
        }
    }
}
