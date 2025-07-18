// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A check on the environment to identify environment health and validate VMware VCF licensing compliance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Check {
    /// <p>The check type. Amazon EVS performs the following checks.</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_REUSE</code>: checks that the VCF license key is not used by another Amazon EVS environment. This check fails if a used license is added to the environment.</p></li>
    /// <li>
    /// <p><code>KEY_COVERAGE</code>: checks that your VCF license key allocates sufficient vCPU cores for all deployed hosts. The check fails when any assigned hosts in the EVS environment are not covered by license keys, or when any unassigned hosts cannot be covered by available vCPU cores in keys.</p></li>
    /// <li>
    /// <p><code>REACHABILITY</code>: checks that the Amazon EVS control plane has a persistent connection to SDDC Manager. If Amazon EVS cannot reach the environment, this check fails.</p></li>
    /// <li>
    /// <p><code>HOST_COUNT</code>: Checks that your environment has a minimum of 4 hosts, which is a requirement for VCF 5.2.1.</p>
    /// <p>If this check fails, you will need to add hosts so that your environment meets this minimum requirement. Amazon EVS only supports environments with 4-16 hosts.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::CheckType>,
    /// <p>The check result.</p>
    pub result: ::std::option::Option<crate::types::CheckResult>,
    /// <p>The time when environment health began to be impaired.</p>
    pub impaired_since: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl Check {
    /// <p>The check type. Amazon EVS performs the following checks.</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_REUSE</code>: checks that the VCF license key is not used by another Amazon EVS environment. This check fails if a used license is added to the environment.</p></li>
    /// <li>
    /// <p><code>KEY_COVERAGE</code>: checks that your VCF license key allocates sufficient vCPU cores for all deployed hosts. The check fails when any assigned hosts in the EVS environment are not covered by license keys, or when any unassigned hosts cannot be covered by available vCPU cores in keys.</p></li>
    /// <li>
    /// <p><code>REACHABILITY</code>: checks that the Amazon EVS control plane has a persistent connection to SDDC Manager. If Amazon EVS cannot reach the environment, this check fails.</p></li>
    /// <li>
    /// <p><code>HOST_COUNT</code>: Checks that your environment has a minimum of 4 hosts, which is a requirement for VCF 5.2.1.</p>
    /// <p>If this check fails, you will need to add hosts so that your environment meets this minimum requirement. Amazon EVS only supports environments with 4-16 hosts.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::CheckType> {
        self.r#type.as_ref()
    }
    /// <p>The check result.</p>
    pub fn result(&self) -> ::std::option::Option<&crate::types::CheckResult> {
        self.result.as_ref()
    }
    /// <p>The time when environment health began to be impaired.</p>
    pub fn impaired_since(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.impaired_since.as_ref()
    }
}
impl Check {
    /// Creates a new builder-style object to manufacture [`Check`](crate::types::Check).
    pub fn builder() -> crate::types::builders::CheckBuilder {
        crate::types::builders::CheckBuilder::default()
    }
}

/// A builder for [`Check`](crate::types::Check).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CheckBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::CheckType>,
    pub(crate) result: ::std::option::Option<crate::types::CheckResult>,
    pub(crate) impaired_since: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl CheckBuilder {
    /// <p>The check type. Amazon EVS performs the following checks.</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_REUSE</code>: checks that the VCF license key is not used by another Amazon EVS environment. This check fails if a used license is added to the environment.</p></li>
    /// <li>
    /// <p><code>KEY_COVERAGE</code>: checks that your VCF license key allocates sufficient vCPU cores for all deployed hosts. The check fails when any assigned hosts in the EVS environment are not covered by license keys, or when any unassigned hosts cannot be covered by available vCPU cores in keys.</p></li>
    /// <li>
    /// <p><code>REACHABILITY</code>: checks that the Amazon EVS control plane has a persistent connection to SDDC Manager. If Amazon EVS cannot reach the environment, this check fails.</p></li>
    /// <li>
    /// <p><code>HOST_COUNT</code>: Checks that your environment has a minimum of 4 hosts, which is a requirement for VCF 5.2.1.</p>
    /// <p>If this check fails, you will need to add hosts so that your environment meets this minimum requirement. Amazon EVS only supports environments with 4-16 hosts.</p></li>
    /// </ul>
    pub fn r#type(mut self, input: crate::types::CheckType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The check type. Amazon EVS performs the following checks.</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_REUSE</code>: checks that the VCF license key is not used by another Amazon EVS environment. This check fails if a used license is added to the environment.</p></li>
    /// <li>
    /// <p><code>KEY_COVERAGE</code>: checks that your VCF license key allocates sufficient vCPU cores for all deployed hosts. The check fails when any assigned hosts in the EVS environment are not covered by license keys, or when any unassigned hosts cannot be covered by available vCPU cores in keys.</p></li>
    /// <li>
    /// <p><code>REACHABILITY</code>: checks that the Amazon EVS control plane has a persistent connection to SDDC Manager. If Amazon EVS cannot reach the environment, this check fails.</p></li>
    /// <li>
    /// <p><code>HOST_COUNT</code>: Checks that your environment has a minimum of 4 hosts, which is a requirement for VCF 5.2.1.</p>
    /// <p>If this check fails, you will need to add hosts so that your environment meets this minimum requirement. Amazon EVS only supports environments with 4-16 hosts.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::CheckType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The check type. Amazon EVS performs the following checks.</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_REUSE</code>: checks that the VCF license key is not used by another Amazon EVS environment. This check fails if a used license is added to the environment.</p></li>
    /// <li>
    /// <p><code>KEY_COVERAGE</code>: checks that your VCF license key allocates sufficient vCPU cores for all deployed hosts. The check fails when any assigned hosts in the EVS environment are not covered by license keys, or when any unassigned hosts cannot be covered by available vCPU cores in keys.</p></li>
    /// <li>
    /// <p><code>REACHABILITY</code>: checks that the Amazon EVS control plane has a persistent connection to SDDC Manager. If Amazon EVS cannot reach the environment, this check fails.</p></li>
    /// <li>
    /// <p><code>HOST_COUNT</code>: Checks that your environment has a minimum of 4 hosts, which is a requirement for VCF 5.2.1.</p>
    /// <p>If this check fails, you will need to add hosts so that your environment meets this minimum requirement. Amazon EVS only supports environments with 4-16 hosts.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::CheckType> {
        &self.r#type
    }
    /// <p>The check result.</p>
    pub fn result(mut self, input: crate::types::CheckResult) -> Self {
        self.result = ::std::option::Option::Some(input);
        self
    }
    /// <p>The check result.</p>
    pub fn set_result(mut self, input: ::std::option::Option<crate::types::CheckResult>) -> Self {
        self.result = input;
        self
    }
    /// <p>The check result.</p>
    pub fn get_result(&self) -> &::std::option::Option<crate::types::CheckResult> {
        &self.result
    }
    /// <p>The time when environment health began to be impaired.</p>
    pub fn impaired_since(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.impaired_since = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when environment health began to be impaired.</p>
    pub fn set_impaired_since(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.impaired_since = input;
        self
    }
    /// <p>The time when environment health began to be impaired.</p>
    pub fn get_impaired_since(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.impaired_since
    }
    /// Consumes the builder and constructs a [`Check`](crate::types::Check).
    pub fn build(self) -> crate::types::Check {
        crate::types::Check {
            r#type: self.r#type,
            result: self.result,
            impaired_since: self.impaired_since,
        }
    }
}
