bindir=${GOPATH}/src/k8s.io
binpath=${bindir}/code-generator/generate-groups.sh
group=traefik
version=v1alpha1
apipath=apis/${group}/${version}
mod=github.com/wwq-2020/ingressroute-conflict-check
tmppath=${GOPATH}/src/${mod}

install: clean gen cp
	
gen:
	${binpath} all  ${mod}/client  ${mod}/apis ${group}:${version}

cp:
	@cp ${tmppath}/${apipath}/zz_generated.deepcopy.go ${apipath}
	@cp -r ${tmppath}/client/* client

clean:
	@rm -rf ${apipath}/zz_generated.deepcopy.go
	@rm -rf client/*

dep: 
	@mkdir -p ${bindir} && cd ${bindir} && git clone https://github.com/kubernetes/code-generator.git