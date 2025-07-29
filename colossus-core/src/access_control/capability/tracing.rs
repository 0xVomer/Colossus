use super::*;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct TracingPublicKey(pub LinkedList<<ElGamal as Nike>::PublicKey>);

impl TracingPublicKey {
    pub(super) fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }
}

impl Serializable for TracingPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.0.len()) + self.0.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.0.len() as u64)?;
        for pk in self.0.iter() {
            n += pk.write(ser)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let n_pk = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut tracers = LinkedList::new();
        for _ in 0..n_pk {
            let tracer = de.read()?;
            tracers.push_back(tracer);
        }
        Ok(Self(tracers))
    }
}
