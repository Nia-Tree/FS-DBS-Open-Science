// Measurement-only fixed-base tables; original protocol and RNG unchanged.
pub struct Zhang23V1Prepared {
    g1: std::sync::Arc<crate::common::FixedBaseTable<G1>>,
    encryption_key: crate::common::FixedBaseTable<G1>,
    target: crate::common::FixedBaseTable<GT>,
}
impl Zhang23V1Prepared {
    pub fn estimated_group_ram_bytes(&self)->usize {self.g1.estimated_group_ram_bytes()+self.encryption_key.estimated_group_ram_bytes()+self.target.estimated_group_ram_bytes()}
}
impl Zhang23 {
    pub fn v1_prepare_online(&self,group:&GroupContext)->Zhang23V1Prepared {
        Zhang23V1Prepared {g1:std::sync::Arc::new(crate::common::FixedBaseTable::new(self.g1)),encryption_key:crate::common::FixedBaseTable::new(group.encryption_key),target:crate::common::FixedBaseTable::new(group.target_key)}
    }
    pub fn v1_prepare_online_for_epoch(&self,previous:&Zhang23V1Prepared,group:&GroupContext)->Zhang23V1Prepared {
        Zhang23V1Prepared {g1:std::sync::Arc::clone(&previous.g1),encryption_key:crate::common::FixedBaseTable::new(group.encryption_key),target:crate::common::FixedBaseTable::new(group.target_key)}
    }
    pub fn v1_sign_encrypt_prepared(&self,sender:&IdentitySecretKey,prepared:&Zhang23V1Prepared,message:&[u8;32],rng:&mut impl RngCore)->Ciphertext {
        let r=random_nonzero_scalar(rng); let c1=prepared.g1.mul(r);let c2=prepared.encryption_key.mul(r);
        let h=crate::baseline_h2c::hash_g2(b"Zhang23/H4",&[&serialize(&c1),message]); let signature=h*sender.u;
        let mut body=Vec::with_capacity(176);body.extend_from_slice(message);body.extend_from_slice(&serialize(&sender.public.x));body.extend_from_slice(&serialize(&signature));
        let pad=kdf_expand_gt(b"Zhang23/H3",&prepared.target.mul(r),body.len());for(byte,mask)in body.iter_mut().zip(pad){*byte^=mask;}
        Ciphertext{c1,c2,encrypted_body:body}
    }
}
#[cfg(test)]
mod v1_cache_tests {
    use super::*;use rand::{rngs::StdRng,SeedableRng};
    #[test]
    fn zhang23_v1_cache_same_ciphertext_and_rng(){
        let mut rng=StdRng::seed_from_u64(230031);let scheme=Zhang23::setup();let sender=scheme.keygen(4,&mut rng);let sks=(1..=3).map(|i|scheme.keygen(i,&mut rng)).collect::<Vec<_>>();
        let group=scheme.prepare_group(&sks,1,&mut rng).unwrap();let prepared=scheme.v1_prepare_online(&group);let mut other=rng.clone();let a=scheme.sign_encrypt(&sender,&group,&[7;32],&mut rng);let b=scheme.v1_sign_encrypt_prepared(&sender,&prepared,&[7;32],&mut other);
        assert_eq!(a.serialized_bytes(),b.serialized_bytes());assert_eq!(rng.next_u64(),other.next_u64());assert_eq!(scheme.decrypt_verify(1,&sender.public,&group,&b),Some([7;32]));
    }
}
