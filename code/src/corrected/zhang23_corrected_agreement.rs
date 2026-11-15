// Full-active one-session §5.2 algebra. Dynamic vacant-slot matrices, Join/Leave
// and the authenticated outside-sender distribution are explicitly excluded.
#[derive(Clone)]pub struct Zhang23AgreementPreparation {id:[u8;16],ids:Vec<usize>,u0:G2,u1:G2,f:Vec<G2>}
#[derive(Clone)]pub struct Zhang23FullContribution {public:IdentityPublicKey,r:G1,values:Vec<G2>}
pub struct Zhang23ColumnFixture {rows:Vec<Zhang23FullContribution>}
impl Zhang23FullContribution{
    pub fn serialized_public_bytes(&self,prep:&Zhang23AgreementPreparation)->Vec<u8>{let mut out=serialize(&self.public.x);out.extend_from_slice(&serialize(&self.r));for(j,x)in self.values.iter().enumerate(){if prep.ids[j]!=self.public.index{out.extend_from_slice(&serialize(x));}}out}
}
impl Zhang23{
    /// Local work for participant 1: its complete row, the public group key,
    /// and its receiver key. Other participants' actual first-column messages
    /// are supplied before timing. No peer's row generation is charged here.
    pub fn paper_local_refresh(&self,member:&IdentitySecretKey,prep:&Zhang23AgreementPreparation,fixture:&mut Zhang23ColumnFixture,rng:&mut impl RngCore)->Option<GroupContext>{
        fixture.rows[0]=self.v1_create_full_contribution(member,prep,rng);
        let public=self.v1_public_from_rows(prep,&fixture.rows)?;
        self.v1_derive_first_receiver_from_column(prep,fixture,&public)
    }
    pub fn v1_prepare_agreement(&self,ids:&[usize],rng:&mut impl RngCore)->Zhang23AgreementPreparation{
        let mut id=[0;16];rng.fill_bytes(&mut id);
        Zhang23AgreementPreparation{id,ids:ids.to_vec(),u0:crate::baseline_h2c::hash_g2(b"Zhang23/H1/0",&[&id]),u1:crate::baseline_h2c::hash_g2(b"Zhang23/H1/1",&[&id]),f:ids.iter().map(|i|crate::baseline_h2c::hash_g2(b"Zhang23/setup/f",&[&(*i as u64).to_le_bytes()])).collect()}
    }
    pub fn v1_create_full_contribution(&self,member:&IdentitySecretKey,prep:&Zhang23AgreementPreparation,rng:&mut impl RngCore)->Zhang23FullContribution{self.v1_create_contribution_columns(member,prep,prep.ids.len(),rng)}
    fn v1_create_contribution_columns(&self,member:&IdentitySecretKey,prep:&Zhang23AgreementPreparation,columns:usize,rng:&mut impl RngCore)->Zhang23FullContribution{
        let z=random_nonzero_scalar(rng);let r=self.g1*z;let p=hash_to_scalar(b"Zhang23/H2",&[&prep.id,&(member.public.index as u64).to_le_bytes(),&serialize(&member.public.x),&serialize(&r)]);
        let base=prep.u0*member.u+prep.u1*(p*member.u);Zhang23FullContribution{public:member.public.clone(),r,values:prep.f.iter().take(columns).map(|f|base+*f*z).collect()}
    }
    pub fn v1_prepare_column_fixture(&self,members:&[IdentitySecretKey],prep:&Zhang23AgreementPreparation,rng:&mut impl RngCore)->Zhang23ColumnFixture{Zhang23ColumnFixture{rows:members.iter().map(|m|self.v1_create_contribution_columns(m,prep,1,rng)).collect()}}
    fn v1_public_from_rows(&self,prep:&Zhang23AgreementPreparation,rows:&[Zhang23FullContribution])->Option<(G1,GT)>{
        if rows.len()!=prep.ids.len()||rows.is_empty(){return None;}let mut y=G1::zero();let mut x=G1::zero();let mut xp=G1::zero();
        for(i,row)in rows.iter().enumerate(){if row.public.index!=prep.ids[i]{return None;}let p=hash_to_scalar(b"Zhang23/H2",&[&prep.id,&(row.public.index as u64).to_le_bytes(),&serialize(&row.public.x),&serialize(&row.r)]);y+=row.r;x+=row.public.x;xp+=row.public.x*p;}
        Some((y,pairing_product(&[(x,prep.u0),(xp,prep.u1)])))
    }
    pub fn v1_public_key_from_column_fixture(&self,prep:&Zhang23AgreementPreparation,fixture:&Zhang23ColumnFixture)->Option<(G1,GT)>{self.v1_public_from_rows(prep,&fixture.rows)}
    pub fn v1_derive_first_receiver_from_column(&self,prep:&Zhang23AgreementPreparation,fixture:&Zhang23ColumnFixture,public:&(G1,GT))->Option<GroupContext>{
        let d=fixture.rows.iter().map(|r|r.values[0]).fold(G2::zero(),|a,b|a+b);
        if pairing(self.g1,d)!=public.1+pairing(public.0,prep.f[0]){return None;}
        Some(GroupContext{recipient_indices:prep.ids.clone(),receiver:prep.ids[0],encryption_key:public.0,target_key:public.1,receiver_key:d,receiver_f:prep.f[0]})
    }
    pub fn v1_agree_real(&self,members:&[IdentitySecretKey],rng:&mut impl RngCore)->Option<GroupEpoch>{
        if members.is_empty(){return None;}let prep=self.v1_prepare_agreement(&members.iter().map(|m|m.public.index).collect::<Vec<_>>(),rng);let rows=members.iter().map(|m|self.v1_create_full_contribution(m,&prep,rng)).collect::<Vec<_>>();let(encryption_key,target_key)=self.v1_public_from_rows(&prep,&rows)?;
        Some(GroupEpoch{recipient_indices:prep.ids,encryption_key,target_key,sum_u:Scalar::zero(),sum_pu:Scalar::zero(),sum_z:Scalar::zero(),group_id:prep.id,real_rows:Some(rows.into_iter().map(|r|r.values).collect()),receiver_points:prep.f})
    }
}
#[cfg(test)]mod corrected_agreement_tests{
    use super::*;use rand::{rngs::StdRng,SeedableRng};use ark_ff::Field;
    #[test]fn zhang23_corrected_real_transcript_matches_algebra_and_rejects_tampering(){let mut rng=StdRng::seed_from_u64(230032);let scheme=Zhang23::setup();let members=(1..=4).map(|i|scheme.keygen(i,&mut rng)).collect::<Vec<_>>();let mut same=rng.clone();let real=scheme.v1_agree_real(&members,&mut rng).unwrap();let algebra=scheme.v1_agree_algebra_fixture(&members,&mut same).unwrap();assert_eq!(real.encryption_key,algebra.encryption_key);assert_eq!(real.target_key,algebra.target_key);assert_eq!(rng.next_u64(),same.next_u64());for i in 1..=4{assert_eq!(scheme.derive_receiver_context(&real,i).unwrap().receiver_key,scheme.derive_receiver_context(&algebra,i).unwrap().receiver_key);}
        let prep=scheme.v1_prepare_agreement(&[1,2,3,4],&mut rng);let mut col=scheme.v1_prepare_column_fixture(&members,&prep,&mut rng);let pk=scheme.v1_public_key_from_column_fixture(&prep,&col).unwrap();assert!(scheme.v1_derive_first_receiver_from_column(&prep,&col,&pk).is_some());col.rows[0].values[0]+=G2::generator();assert!(scheme.v1_derive_first_receiver_from_column(&prep,&col,&pk).is_none());}
    #[test]fn zhang23_corrected_old_signature_rescaling_fails(){let mut rng=StdRng::seed_from_u64(230033);let scheme=Zhang23::setup();let sender=scheme.keygen(1,&mut rng);let c1=scheme.g1*random_nonzero_scalar(&mut rng);let encoded=serialize(&c1);let old_h=hash_to_scalar(b"Zhang23/H4",&[&encoded,&[1;32]]);let actual_h=crate::baseline_h2c::hash_g2(b"Zhang23/H4",&[&encoded,&[1;32]]);let sigma=actual_h*sender.u;let false_u2=sigma*old_h.inverse().unwrap();let new_old_h=hash_to_scalar(b"Zhang23/H4",&[&encoded,&[2;32]]);let forged=false_u2*new_old_h;let new_h=crate::baseline_h2c::hash_g2(b"Zhang23/H4",&[&encoded,&[2;32]]);assert!(!pairing_product(&[(scheme.g1,forged),(-sender.public.x,new_h)]).is_zero());}
}
