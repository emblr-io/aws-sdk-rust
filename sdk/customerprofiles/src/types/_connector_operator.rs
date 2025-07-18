// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The operation to be performed on the provided source fields.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConnectorOperator {
    /// <p>The operation to be performed on the provided Marketo source fields.</p>
    pub marketo: ::std::option::Option<crate::types::MarketoConnectorOperator>,
    /// <p>The operation to be performed on the provided Amazon S3 source fields.</p>
    pub s3: ::std::option::Option<crate::types::S3ConnectorOperator>,
    /// <p>The operation to be performed on the provided Salesforce source fields.</p>
    pub salesforce: ::std::option::Option<crate::types::SalesforceConnectorOperator>,
    /// <p>The operation to be performed on the provided ServiceNow source fields.</p>
    pub service_now: ::std::option::Option<crate::types::ServiceNowConnectorOperator>,
    /// <p>The operation to be performed on the provided Zendesk source fields.</p>
    pub zendesk: ::std::option::Option<crate::types::ZendeskConnectorOperator>,
}
impl ConnectorOperator {
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
    /// <p>The operation to be performed on the provided Zendesk source fields.</p>
    pub fn zendesk(&self) -> ::std::option::Option<&crate::types::ZendeskConnectorOperator> {
        self.zendesk.as_ref()
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
    pub(crate) marketo: ::std::option::Option<crate::types::MarketoConnectorOperator>,
    pub(crate) s3: ::std::option::Option<crate::types::S3ConnectorOperator>,
    pub(crate) salesforce: ::std::option::Option<crate::types::SalesforceConnectorOperator>,
    pub(crate) service_now: ::std::option::Option<crate::types::ServiceNowConnectorOperator>,
    pub(crate) zendesk: ::std::option::Option<crate::types::ZendeskConnectorOperator>,
}
impl ConnectorOperatorBuilder {
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
    /// Consumes the builder and constructs a [`ConnectorOperator`](crate::types::ConnectorOperator).
    pub fn build(self) -> crate::types::ConnectorOperator {
        crate::types::ConnectorOperator {
            marketo: self.marketo,
            s3: self.s3,
            salesforce: self.salesforce,
            service_now: self.service_now,
            zendesk: self.zendesk,
        }
    }
}
