// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A container for the request parameters associated with an asynchronous request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AsyncRequestParameters {
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_CreateMultiRegionAccessPoint.html">CreateMultiRegionAccessPoint</a> request.</p>
    pub create_multi_region_access_point_request: ::std::option::Option<crate::types::CreateMultiRegionAccessPointInput>,
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_DeleteMultiRegionAccessPoint.html">DeleteMultiRegionAccessPoint</a> request.</p>
    pub delete_multi_region_access_point_request: ::std::option::Option<crate::types::DeleteMultiRegionAccessPointInput>,
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_PutMultiRegionAccessPoint.html">PutMultiRegionAccessPoint</a> request.</p>
    pub put_multi_region_access_point_policy_request: ::std::option::Option<crate::types::PutMultiRegionAccessPointPolicyInput>,
}
impl AsyncRequestParameters {
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_CreateMultiRegionAccessPoint.html">CreateMultiRegionAccessPoint</a> request.</p>
    pub fn create_multi_region_access_point_request(&self) -> ::std::option::Option<&crate::types::CreateMultiRegionAccessPointInput> {
        self.create_multi_region_access_point_request.as_ref()
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_DeleteMultiRegionAccessPoint.html">DeleteMultiRegionAccessPoint</a> request.</p>
    pub fn delete_multi_region_access_point_request(&self) -> ::std::option::Option<&crate::types::DeleteMultiRegionAccessPointInput> {
        self.delete_multi_region_access_point_request.as_ref()
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_PutMultiRegionAccessPoint.html">PutMultiRegionAccessPoint</a> request.</p>
    pub fn put_multi_region_access_point_policy_request(&self) -> ::std::option::Option<&crate::types::PutMultiRegionAccessPointPolicyInput> {
        self.put_multi_region_access_point_policy_request.as_ref()
    }
}
impl AsyncRequestParameters {
    /// Creates a new builder-style object to manufacture [`AsyncRequestParameters`](crate::types::AsyncRequestParameters).
    pub fn builder() -> crate::types::builders::AsyncRequestParametersBuilder {
        crate::types::builders::AsyncRequestParametersBuilder::default()
    }
}

/// A builder for [`AsyncRequestParameters`](crate::types::AsyncRequestParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AsyncRequestParametersBuilder {
    pub(crate) create_multi_region_access_point_request: ::std::option::Option<crate::types::CreateMultiRegionAccessPointInput>,
    pub(crate) delete_multi_region_access_point_request: ::std::option::Option<crate::types::DeleteMultiRegionAccessPointInput>,
    pub(crate) put_multi_region_access_point_policy_request: ::std::option::Option<crate::types::PutMultiRegionAccessPointPolicyInput>,
}
impl AsyncRequestParametersBuilder {
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_CreateMultiRegionAccessPoint.html">CreateMultiRegionAccessPoint</a> request.</p>
    pub fn create_multi_region_access_point_request(mut self, input: crate::types::CreateMultiRegionAccessPointInput) -> Self {
        self.create_multi_region_access_point_request = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_CreateMultiRegionAccessPoint.html">CreateMultiRegionAccessPoint</a> request.</p>
    pub fn set_create_multi_region_access_point_request(
        mut self,
        input: ::std::option::Option<crate::types::CreateMultiRegionAccessPointInput>,
    ) -> Self {
        self.create_multi_region_access_point_request = input;
        self
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_CreateMultiRegionAccessPoint.html">CreateMultiRegionAccessPoint</a> request.</p>
    pub fn get_create_multi_region_access_point_request(&self) -> &::std::option::Option<crate::types::CreateMultiRegionAccessPointInput> {
        &self.create_multi_region_access_point_request
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_DeleteMultiRegionAccessPoint.html">DeleteMultiRegionAccessPoint</a> request.</p>
    pub fn delete_multi_region_access_point_request(mut self, input: crate::types::DeleteMultiRegionAccessPointInput) -> Self {
        self.delete_multi_region_access_point_request = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_DeleteMultiRegionAccessPoint.html">DeleteMultiRegionAccessPoint</a> request.</p>
    pub fn set_delete_multi_region_access_point_request(
        mut self,
        input: ::std::option::Option<crate::types::DeleteMultiRegionAccessPointInput>,
    ) -> Self {
        self.delete_multi_region_access_point_request = input;
        self
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_DeleteMultiRegionAccessPoint.html">DeleteMultiRegionAccessPoint</a> request.</p>
    pub fn get_delete_multi_region_access_point_request(&self) -> &::std::option::Option<crate::types::DeleteMultiRegionAccessPointInput> {
        &self.delete_multi_region_access_point_request
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_PutMultiRegionAccessPoint.html">PutMultiRegionAccessPoint</a> request.</p>
    pub fn put_multi_region_access_point_policy_request(mut self, input: crate::types::PutMultiRegionAccessPointPolicyInput) -> Self {
        self.put_multi_region_access_point_policy_request = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_PutMultiRegionAccessPoint.html">PutMultiRegionAccessPoint</a> request.</p>
    pub fn set_put_multi_region_access_point_policy_request(
        mut self,
        input: ::std::option::Option<crate::types::PutMultiRegionAccessPointPolicyInput>,
    ) -> Self {
        self.put_multi_region_access_point_policy_request = input;
        self
    }
    /// <p>A container of the parameters for a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_PutMultiRegionAccessPoint.html">PutMultiRegionAccessPoint</a> request.</p>
    pub fn get_put_multi_region_access_point_policy_request(&self) -> &::std::option::Option<crate::types::PutMultiRegionAccessPointPolicyInput> {
        &self.put_multi_region_access_point_policy_request
    }
    /// Consumes the builder and constructs a [`AsyncRequestParameters`](crate::types::AsyncRequestParameters).
    pub fn build(self) -> crate::types::AsyncRequestParameters {
        crate::types::AsyncRequestParameters {
            create_multi_region_access_point_request: self.create_multi_region_access_point_request,
            delete_multi_region_access_point_request: self.delete_multi_region_access_point_request,
            put_multi_region_access_point_policy_request: self.put_multi_region_access_point_policy_request,
        }
    }
}
