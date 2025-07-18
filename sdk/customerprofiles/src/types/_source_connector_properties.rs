// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the information that is required to query a particular Amazon AppFlow connector. Customer Profiles supports Salesforce, Zendesk, Marketo, ServiceNow and Amazon S3.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SourceConnectorProperties {
    /// <p>The properties that are applied when Marketo is being used as a source.</p>
    pub marketo: ::std::option::Option<crate::types::MarketoSourceProperties>,
    /// <p>The properties that are applied when Amazon S3 is being used as the flow source.</p>
    pub s3: ::std::option::Option<crate::types::S3SourceProperties>,
    /// <p>The properties that are applied when Salesforce is being used as a source.</p>
    pub salesforce: ::std::option::Option<crate::types::SalesforceSourceProperties>,
    /// <p>The properties that are applied when ServiceNow is being used as a source.</p>
    pub service_now: ::std::option::Option<crate::types::ServiceNowSourceProperties>,
    /// <p>The properties that are applied when using Zendesk as a flow source.</p>
    pub zendesk: ::std::option::Option<crate::types::ZendeskSourceProperties>,
}
impl SourceConnectorProperties {
    /// <p>The properties that are applied when Marketo is being used as a source.</p>
    pub fn marketo(&self) -> ::std::option::Option<&crate::types::MarketoSourceProperties> {
        self.marketo.as_ref()
    }
    /// <p>The properties that are applied when Amazon S3 is being used as the flow source.</p>
    pub fn s3(&self) -> ::std::option::Option<&crate::types::S3SourceProperties> {
        self.s3.as_ref()
    }
    /// <p>The properties that are applied when Salesforce is being used as a source.</p>
    pub fn salesforce(&self) -> ::std::option::Option<&crate::types::SalesforceSourceProperties> {
        self.salesforce.as_ref()
    }
    /// <p>The properties that are applied when ServiceNow is being used as a source.</p>
    pub fn service_now(&self) -> ::std::option::Option<&crate::types::ServiceNowSourceProperties> {
        self.service_now.as_ref()
    }
    /// <p>The properties that are applied when using Zendesk as a flow source.</p>
    pub fn zendesk(&self) -> ::std::option::Option<&crate::types::ZendeskSourceProperties> {
        self.zendesk.as_ref()
    }
}
impl SourceConnectorProperties {
    /// Creates a new builder-style object to manufacture [`SourceConnectorProperties`](crate::types::SourceConnectorProperties).
    pub fn builder() -> crate::types::builders::SourceConnectorPropertiesBuilder {
        crate::types::builders::SourceConnectorPropertiesBuilder::default()
    }
}

/// A builder for [`SourceConnectorProperties`](crate::types::SourceConnectorProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceConnectorPropertiesBuilder {
    pub(crate) marketo: ::std::option::Option<crate::types::MarketoSourceProperties>,
    pub(crate) s3: ::std::option::Option<crate::types::S3SourceProperties>,
    pub(crate) salesforce: ::std::option::Option<crate::types::SalesforceSourceProperties>,
    pub(crate) service_now: ::std::option::Option<crate::types::ServiceNowSourceProperties>,
    pub(crate) zendesk: ::std::option::Option<crate::types::ZendeskSourceProperties>,
}
impl SourceConnectorPropertiesBuilder {
    /// <p>The properties that are applied when Marketo is being used as a source.</p>
    pub fn marketo(mut self, input: crate::types::MarketoSourceProperties) -> Self {
        self.marketo = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties that are applied when Marketo is being used as a source.</p>
    pub fn set_marketo(mut self, input: ::std::option::Option<crate::types::MarketoSourceProperties>) -> Self {
        self.marketo = input;
        self
    }
    /// <p>The properties that are applied when Marketo is being used as a source.</p>
    pub fn get_marketo(&self) -> &::std::option::Option<crate::types::MarketoSourceProperties> {
        &self.marketo
    }
    /// <p>The properties that are applied when Amazon S3 is being used as the flow source.</p>
    pub fn s3(mut self, input: crate::types::S3SourceProperties) -> Self {
        self.s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties that are applied when Amazon S3 is being used as the flow source.</p>
    pub fn set_s3(mut self, input: ::std::option::Option<crate::types::S3SourceProperties>) -> Self {
        self.s3 = input;
        self
    }
    /// <p>The properties that are applied when Amazon S3 is being used as the flow source.</p>
    pub fn get_s3(&self) -> &::std::option::Option<crate::types::S3SourceProperties> {
        &self.s3
    }
    /// <p>The properties that are applied when Salesforce is being used as a source.</p>
    pub fn salesforce(mut self, input: crate::types::SalesforceSourceProperties) -> Self {
        self.salesforce = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties that are applied when Salesforce is being used as a source.</p>
    pub fn set_salesforce(mut self, input: ::std::option::Option<crate::types::SalesforceSourceProperties>) -> Self {
        self.salesforce = input;
        self
    }
    /// <p>The properties that are applied when Salesforce is being used as a source.</p>
    pub fn get_salesforce(&self) -> &::std::option::Option<crate::types::SalesforceSourceProperties> {
        &self.salesforce
    }
    /// <p>The properties that are applied when ServiceNow is being used as a source.</p>
    pub fn service_now(mut self, input: crate::types::ServiceNowSourceProperties) -> Self {
        self.service_now = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties that are applied when ServiceNow is being used as a source.</p>
    pub fn set_service_now(mut self, input: ::std::option::Option<crate::types::ServiceNowSourceProperties>) -> Self {
        self.service_now = input;
        self
    }
    /// <p>The properties that are applied when ServiceNow is being used as a source.</p>
    pub fn get_service_now(&self) -> &::std::option::Option<crate::types::ServiceNowSourceProperties> {
        &self.service_now
    }
    /// <p>The properties that are applied when using Zendesk as a flow source.</p>
    pub fn zendesk(mut self, input: crate::types::ZendeskSourceProperties) -> Self {
        self.zendesk = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties that are applied when using Zendesk as a flow source.</p>
    pub fn set_zendesk(mut self, input: ::std::option::Option<crate::types::ZendeskSourceProperties>) -> Self {
        self.zendesk = input;
        self
    }
    /// <p>The properties that are applied when using Zendesk as a flow source.</p>
    pub fn get_zendesk(&self) -> &::std::option::Option<crate::types::ZendeskSourceProperties> {
        &self.zendesk
    }
    /// Consumes the builder and constructs a [`SourceConnectorProperties`](crate::types::SourceConnectorProperties).
    pub fn build(self) -> crate::types::SourceConnectorProperties {
        crate::types::SourceConnectorProperties {
            marketo: self.marketo,
            s3: self.s3,
            salesforce: self.salesforce,
            service_now: self.service_now,
            zendesk: self.zendesk,
        }
    }
}
