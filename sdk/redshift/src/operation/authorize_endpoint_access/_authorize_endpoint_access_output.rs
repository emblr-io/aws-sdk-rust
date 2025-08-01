// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an endpoint authorization for authorizing Redshift-managed VPC endpoint access to a cluster across Amazon Web Services accounts.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AuthorizeEndpointAccessOutput {
    /// <p>The Amazon Web Services account ID of the cluster owner.</p>
    pub grantor: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID of the grantee of the cluster.</p>
    pub grantee: ::std::option::Option<::std::string::String>,
    /// <p>The cluster identifier.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The time (UTC) when the authorization was created.</p>
    pub authorize_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the cluster.</p>
    pub cluster_status: ::std::option::Option<::std::string::String>,
    /// <p>The status of the authorization action.</p>
    pub status: ::std::option::Option<crate::types::AuthorizationStatus>,
    /// <p>Indicates whether all VPCs in the grantee account are allowed access to the cluster.</p>
    pub allowed_all_vpcs: ::std::option::Option<bool>,
    /// <p>The VPCs allowed access to the cluster.</p>
    pub allowed_vpcs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The number of Redshift-managed VPC endpoints created for the authorization.</p>
    pub endpoint_count: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl AuthorizeEndpointAccessOutput {
    /// <p>The Amazon Web Services account ID of the cluster owner.</p>
    pub fn grantor(&self) -> ::std::option::Option<&str> {
        self.grantor.as_deref()
    }
    /// <p>The Amazon Web Services account ID of the grantee of the cluster.</p>
    pub fn grantee(&self) -> ::std::option::Option<&str> {
        self.grantee.as_deref()
    }
    /// <p>The cluster identifier.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>The time (UTC) when the authorization was created.</p>
    pub fn authorize_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.authorize_time.as_ref()
    }
    /// <p>The status of the cluster.</p>
    pub fn cluster_status(&self) -> ::std::option::Option<&str> {
        self.cluster_status.as_deref()
    }
    /// <p>The status of the authorization action.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AuthorizationStatus> {
        self.status.as_ref()
    }
    /// <p>Indicates whether all VPCs in the grantee account are allowed access to the cluster.</p>
    pub fn allowed_all_vpcs(&self) -> ::std::option::Option<bool> {
        self.allowed_all_vpcs
    }
    /// <p>The VPCs allowed access to the cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.allowed_vpcs.is_none()`.
    pub fn allowed_vpcs(&self) -> &[::std::string::String] {
        self.allowed_vpcs.as_deref().unwrap_or_default()
    }
    /// <p>The number of Redshift-managed VPC endpoints created for the authorization.</p>
    pub fn endpoint_count(&self) -> ::std::option::Option<i32> {
        self.endpoint_count
    }
}
impl ::aws_types::request_id::RequestId for AuthorizeEndpointAccessOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AuthorizeEndpointAccessOutput {
    /// Creates a new builder-style object to manufacture [`AuthorizeEndpointAccessOutput`](crate::operation::authorize_endpoint_access::AuthorizeEndpointAccessOutput).
    pub fn builder() -> crate::operation::authorize_endpoint_access::builders::AuthorizeEndpointAccessOutputBuilder {
        crate::operation::authorize_endpoint_access::builders::AuthorizeEndpointAccessOutputBuilder::default()
    }
}

/// A builder for [`AuthorizeEndpointAccessOutput`](crate::operation::authorize_endpoint_access::AuthorizeEndpointAccessOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AuthorizeEndpointAccessOutputBuilder {
    pub(crate) grantor: ::std::option::Option<::std::string::String>,
    pub(crate) grantee: ::std::option::Option<::std::string::String>,
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) authorize_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) cluster_status: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::AuthorizationStatus>,
    pub(crate) allowed_all_vpcs: ::std::option::Option<bool>,
    pub(crate) allowed_vpcs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) endpoint_count: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl AuthorizeEndpointAccessOutputBuilder {
    /// <p>The Amazon Web Services account ID of the cluster owner.</p>
    pub fn grantor(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grantor = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the cluster owner.</p>
    pub fn set_grantor(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grantor = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the cluster owner.</p>
    pub fn get_grantor(&self) -> &::std::option::Option<::std::string::String> {
        &self.grantor
    }
    /// <p>The Amazon Web Services account ID of the grantee of the cluster.</p>
    pub fn grantee(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.grantee = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the grantee of the cluster.</p>
    pub fn set_grantee(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.grantee = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the grantee of the cluster.</p>
    pub fn get_grantee(&self) -> &::std::option::Option<::std::string::String> {
        &self.grantee
    }
    /// <p>The cluster identifier.</p>
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster identifier.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The cluster identifier.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>The time (UTC) when the authorization was created.</p>
    pub fn authorize_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.authorize_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time (UTC) when the authorization was created.</p>
    pub fn set_authorize_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.authorize_time = input;
        self
    }
    /// <p>The time (UTC) when the authorization was created.</p>
    pub fn get_authorize_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.authorize_time
    }
    /// <p>The status of the cluster.</p>
    pub fn cluster_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the cluster.</p>
    pub fn set_cluster_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_status = input;
        self
    }
    /// <p>The status of the cluster.</p>
    pub fn get_cluster_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_status
    }
    /// <p>The status of the authorization action.</p>
    pub fn status(mut self, input: crate::types::AuthorizationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the authorization action.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AuthorizationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the authorization action.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AuthorizationStatus> {
        &self.status
    }
    /// <p>Indicates whether all VPCs in the grantee account are allowed access to the cluster.</p>
    pub fn allowed_all_vpcs(mut self, input: bool) -> Self {
        self.allowed_all_vpcs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether all VPCs in the grantee account are allowed access to the cluster.</p>
    pub fn set_allowed_all_vpcs(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allowed_all_vpcs = input;
        self
    }
    /// <p>Indicates whether all VPCs in the grantee account are allowed access to the cluster.</p>
    pub fn get_allowed_all_vpcs(&self) -> &::std::option::Option<bool> {
        &self.allowed_all_vpcs
    }
    /// Appends an item to `allowed_vpcs`.
    ///
    /// To override the contents of this collection use [`set_allowed_vpcs`](Self::set_allowed_vpcs).
    ///
    /// <p>The VPCs allowed access to the cluster.</p>
    pub fn allowed_vpcs(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.allowed_vpcs.unwrap_or_default();
        v.push(input.into());
        self.allowed_vpcs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The VPCs allowed access to the cluster.</p>
    pub fn set_allowed_vpcs(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.allowed_vpcs = input;
        self
    }
    /// <p>The VPCs allowed access to the cluster.</p>
    pub fn get_allowed_vpcs(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.allowed_vpcs
    }
    /// <p>The number of Redshift-managed VPC endpoints created for the authorization.</p>
    pub fn endpoint_count(mut self, input: i32) -> Self {
        self.endpoint_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of Redshift-managed VPC endpoints created for the authorization.</p>
    pub fn set_endpoint_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.endpoint_count = input;
        self
    }
    /// <p>The number of Redshift-managed VPC endpoints created for the authorization.</p>
    pub fn get_endpoint_count(&self) -> &::std::option::Option<i32> {
        &self.endpoint_count
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AuthorizeEndpointAccessOutput`](crate::operation::authorize_endpoint_access::AuthorizeEndpointAccessOutput).
    pub fn build(self) -> crate::operation::authorize_endpoint_access::AuthorizeEndpointAccessOutput {
        crate::operation::authorize_endpoint_access::AuthorizeEndpointAccessOutput {
            grantor: self.grantor,
            grantee: self.grantee,
            cluster_identifier: self.cluster_identifier,
            authorize_time: self.authorize_time,
            cluster_status: self.cluster_status,
            status: self.status,
            allowed_all_vpcs: self.allowed_all_vpcs,
            allowed_vpcs: self.allowed_vpcs,
            endpoint_count: self.endpoint_count,
            _request_id: self._request_id,
        }
    }
}
