// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The deregistration policy for the data that's stored in Audit Manager. You can use this attribute to determine how your data is handled when you <a href="https://docs.aws.amazon.com/audit-manager/latest/APIReference/API_DeregisterAccount.html">deregister Audit Manager</a>.</p>
/// <p>By default, Audit Manager retains evidence data for two years from the time of its creation. Other Audit Manager resources (including assessments, custom controls, and custom frameworks) remain in Audit Manager indefinitely, and are available if you <a href="https://docs.aws.amazon.com/audit-manager/latest/APIReference/API_RegisterAccount.html">re-register Audit Manager</a> in the future. For more information about data retention, see <a href="https://docs.aws.amazon.com/audit-manager/latest/userguide/data-protection.html">Data Protection</a> in the <i>Audit Manager User Guide</i>.</p><important>
/// <p>If you choose to delete all data, this action permanently deletes all evidence data in your account within seven days. It also deletes all of the Audit Manager resources that you created, including assessments, custom controls, and custom frameworks. Your data will not be available if you re-register Audit Manager in the future.</p>
/// </important>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregistrationPolicy {
    /// <p>Specifies which Audit Manager data will be deleted when you deregister Audit Manager.</p>
    /// <ul>
    /// <li>
    /// <p>If you set the value to <code>ALL</code>, all of your data is deleted within seven days of deregistration.</p></li>
    /// <li>
    /// <p>If you set the value to <code>DEFAULT</code>, none of your data is deleted at the time of deregistration. However, keep in mind that the Audit Manager data retention policy still applies. As a result, any evidence data will be deleted two years after its creation date. Your other Audit Manager resources will continue to exist indefinitely.</p></li>
    /// </ul>
    pub delete_resources: ::std::option::Option<crate::types::DeleteResources>,
}
impl DeregistrationPolicy {
    /// <p>Specifies which Audit Manager data will be deleted when you deregister Audit Manager.</p>
    /// <ul>
    /// <li>
    /// <p>If you set the value to <code>ALL</code>, all of your data is deleted within seven days of deregistration.</p></li>
    /// <li>
    /// <p>If you set the value to <code>DEFAULT</code>, none of your data is deleted at the time of deregistration. However, keep in mind that the Audit Manager data retention policy still applies. As a result, any evidence data will be deleted two years after its creation date. Your other Audit Manager resources will continue to exist indefinitely.</p></li>
    /// </ul>
    pub fn delete_resources(&self) -> ::std::option::Option<&crate::types::DeleteResources> {
        self.delete_resources.as_ref()
    }
}
impl DeregistrationPolicy {
    /// Creates a new builder-style object to manufacture [`DeregistrationPolicy`](crate::types::DeregistrationPolicy).
    pub fn builder() -> crate::types::builders::DeregistrationPolicyBuilder {
        crate::types::builders::DeregistrationPolicyBuilder::default()
    }
}

/// A builder for [`DeregistrationPolicy`](crate::types::DeregistrationPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregistrationPolicyBuilder {
    pub(crate) delete_resources: ::std::option::Option<crate::types::DeleteResources>,
}
impl DeregistrationPolicyBuilder {
    /// <p>Specifies which Audit Manager data will be deleted when you deregister Audit Manager.</p>
    /// <ul>
    /// <li>
    /// <p>If you set the value to <code>ALL</code>, all of your data is deleted within seven days of deregistration.</p></li>
    /// <li>
    /// <p>If you set the value to <code>DEFAULT</code>, none of your data is deleted at the time of deregistration. However, keep in mind that the Audit Manager data retention policy still applies. As a result, any evidence data will be deleted two years after its creation date. Your other Audit Manager resources will continue to exist indefinitely.</p></li>
    /// </ul>
    pub fn delete_resources(mut self, input: crate::types::DeleteResources) -> Self {
        self.delete_resources = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies which Audit Manager data will be deleted when you deregister Audit Manager.</p>
    /// <ul>
    /// <li>
    /// <p>If you set the value to <code>ALL</code>, all of your data is deleted within seven days of deregistration.</p></li>
    /// <li>
    /// <p>If you set the value to <code>DEFAULT</code>, none of your data is deleted at the time of deregistration. However, keep in mind that the Audit Manager data retention policy still applies. As a result, any evidence data will be deleted two years after its creation date. Your other Audit Manager resources will continue to exist indefinitely.</p></li>
    /// </ul>
    pub fn set_delete_resources(mut self, input: ::std::option::Option<crate::types::DeleteResources>) -> Self {
        self.delete_resources = input;
        self
    }
    /// <p>Specifies which Audit Manager data will be deleted when you deregister Audit Manager.</p>
    /// <ul>
    /// <li>
    /// <p>If you set the value to <code>ALL</code>, all of your data is deleted within seven days of deregistration.</p></li>
    /// <li>
    /// <p>If you set the value to <code>DEFAULT</code>, none of your data is deleted at the time of deregistration. However, keep in mind that the Audit Manager data retention policy still applies. As a result, any evidence data will be deleted two years after its creation date. Your other Audit Manager resources will continue to exist indefinitely.</p></li>
    /// </ul>
    pub fn get_delete_resources(&self) -> &::std::option::Option<crate::types::DeleteResources> {
        &self.delete_resources
    }
    /// Consumes the builder and constructs a [`DeregistrationPolicy`](crate::types::DeregistrationPolicy).
    pub fn build(self) -> crate::types::DeregistrationPolicy {
        crate::types::DeregistrationPolicy {
            delete_resources: self.delete_resources,
        }
    }
}
